// Code generated by "stringer -type=CiphertextType"; DO NOT EDIT.

package message

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[WhisperType-2]
	_ = x[PreKeyType-3]
	_ = x[SenderKeyType-7]
	_ = x[PlaintextType-8]
}

const (
	_CiphertextType_name_0 = "WhisperTypePreKeyType"
	_CiphertextType_name_1 = "SenderKeyTypePlaintextType"
)

var (
	_CiphertextType_index_0 = [...]uint8{0, 11, 21}
	_CiphertextType_index_1 = [...]uint8{0, 13, 26}
)

func (i CiphertextType) String() string {
	switch {
	case 2 <= i && i <= 3:
		i -= 2
		return _CiphertextType_name_0[_CiphertextType_index_0[i]:_CiphertextType_index_0[i+1]]
	case 7 <= i && i <= 8:
		i -= 7
		return _CiphertextType_name_1[_CiphertextType_index_1[i]:_CiphertextType_index_1[i+1]]
	default:
		return "CiphertextType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
