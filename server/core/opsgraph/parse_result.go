package opsgraph

type ParseResult struct {
	ParserName  string       `json:"parser_name"`
	Nodes       []Node       `json:"nodes"`
	Edges       []Edge       `json:"edges"`
	Evidence    []Evidence   `json:"evidence"`
	Confidence  float64      `json:"confidence"`
	ParseErrors []ParseError `json:"parse_errors"`
}
