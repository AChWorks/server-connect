package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// encoding/json deliberately accepts duplicate members and matches Go struct
// fields case-insensitively. Neither behavior is acceptable for persistence
// that may later mediate privileged network recovery. Validate the complete
// bounded token tree BEFORE any decoding or canonicalization.
func rejectAmbiguousJournalJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > activationJournalMaxBytes || !utf8.Valid(raw) {
		return activationJournalError("journal JSON is absent, invalid UTF-8 or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	budget := 65536
	if err := scanStrictJournalValue(decoder, 0, &budget); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return activationJournalError("journal JSON has trailing values")
	}
	return nil
}

func scanStrictJournalValue(decoder *json.Decoder, depth int, budget *int) error {
	*budget = *budget - 1
	if *budget < 0 || depth > 32 {
		return activationJournalError("journal JSON exceeds bounded structural complexity")
	}
	token, err := decoder.Token()
	if err != nil {
		return activationJournalError("journal JSON syntax is invalid")
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return activationJournalError("journal JSON object member is invalid")
			}
			// Case-folding is intentionally conservative for opaque
			// kernel resource evidence as well as known schema keys.
			folded := strings.ToLower(key)
			if seen[folded] {
				return activationJournalError("journal JSON contains duplicate or case-ambiguous object members")
			}
			seen[folded] = true
			if err := scanStrictJournalValue(decoder, depth+1, budget); err != nil {
				return err
			}
		}
		close, err := decoder.Token()
		if err != nil || close != json.Delim('}') {
			return activationJournalError("journal JSON object is unterminated")
		}
	case '[':
		for decoder.More() {
			if err := scanStrictJournalValue(decoder, depth+1, budget); err != nil {
				return err
			}
		}
		close, err := decoder.Token()
		if err != nil || close != json.Delim(']') {
			return activationJournalError("journal JSON array is unterminated")
		}
	default:
		return activationJournalError("journal JSON has unexpected structural token")
	}
	return nil
}

var activationJournalFields = map[string]bool{
	"version": true, "revision": true, "operation_id": true, "phase": true,
	"created_unix": true, "observation_sha256": true,
	"plan_sha256": true, "changes": true,
}

// The exact v1 selective subtype is opt-in. Legacy generic records cannot
// be silently reinterpreted as selective, and future variants fail closed.
var selectiveJournalFields = map[string]bool{
	"version": true, "revision": true, "operation_id": true, "phase": true,
	"created_unix": true, "observation_sha256": true,
	"plan_sha256": true, "changes": true,
	"intent_type": true, "selective": true,
}
var selectiveJournalBindingFields = map[string]bool{
	"endpoint": true, "management_peer": true,
	"tunnel_interface": true, "route_table": true,
}

var activationChangeFields = map[string]bool{
	"kind": true, "key": true, "before": true,
	"intended": true, "stage": true,
}

func requireExactJournalKeys(raw json.RawMessage, allowed map[string]bool) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || len(object) != len(allowed) {
		return activationJournalError("activation journal schema has missing, unknown or aliased object members")
	}
	for key := range object {
		if !allowed[key] {
			return activationJournalError("activation journal schema has unknown or case-variant member")
		}
	}
	return nil
}

func strictActivationJournalJSON(data []byte) error {
	if err := rejectAmbiguousJournalJSON(data); err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return activationJournalError("activation journal root is malformed")
	}
	if raw, hasType := root["intent_type"]; hasType {
		var intentType string
		if err := json.Unmarshal(raw, &intentType); err != nil || intentType != selectiveIntentType {
			return activationJournalError("unsupported activation intent subtype")
		}
		if err := requireExactJournalKeys(data, selectiveJournalFields); err != nil {
			return err
		}
		if err := requireExactJournalKeys(root["selective"], selectiveJournalBindingFields); err != nil {
			return err
		}
	} else if err := requireExactJournalKeys(data, activationJournalFields); err != nil {
		return err
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(root["changes"], &rows); err != nil ||
		len(rows) == 0 || len(rows) > activationJournalMaxItems {
		return activationJournalError("activation journal changes must be a bounded array")
	}
	for _, row := range rows {
		if err := requireExactJournalKeys(row, activationChangeFields); err != nil {
			return err
		}
	}
	return nil
}
