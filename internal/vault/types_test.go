package vault

import (
	"testing"
	"time"
)

func TestNewRecordIDAndRecordValidation(t *testing.T) {
	id, err := NewRecordID()
	if err != nil {
		t.Fatalf("NewRecordID returned error: %v", err)
	}
	if len(id) != 32 {
		t.Fatalf("id length = %d, want 32", len(id))
	}

	if err := (DataType("unknown")).Validate(); err == nil {
		t.Fatal("unsupported data type accepted")
	}
	if err := (Record{ID: "record-1", Type: DataTypeText, Payload: "payload"}).Validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if err := (Record{ID: "record-1", Type: DataTypeText, Deleted: true}).Validate(); err != nil {
		t.Fatalf("deleted record without payload rejected: %v", err)
	}
	if err := (Record{ID: "", Type: DataTypeText, Payload: "payload"}).Validate(); err == nil {
		t.Fatal("record without id accepted")
	}
	if err := (Record{ID: "record-1", Type: DataTypeText}).Validate(); err == nil {
		t.Fatal("record without payload accepted")
	}
}

func TestNewEncryptedRecordGeneratesID(t *testing.T) {
	record, err := NewEncryptedRecord("master", "", DataTypeText, SecretData{
		Name:   "note",
		Fields: map[string]string{"text": "hello"},
	}, zeroTime())
	if err != nil {
		t.Fatalf("NewEncryptedRecord returned error: %v", err)
	}
	if record.ID == "" {
		t.Fatal("NewEncryptedRecord returned empty generated id")
	}
}

func zeroTime() time.Time {
	return time.Time{}
}
