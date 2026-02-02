open Ast

(** Module embedding function to make a program corresponding to the automaton described in the CSL specification. Let a submitted command sequence, the automaton will output on {i stderr} ["OK"] if the command sequence should be accepted by the network protocol implementation, or an error if not. In addition, the status code is [0] in case of legal command sequence, [1] otherwise. *)

(**
  Example of code to compile the generated automaton :
  {[
    let _ = Sys.command (Filename.quote_command ("ocamllex") ["lexer.mll"]) in
    let _ = Sys.command (Filename.quote_command ("menhir") ["parser.mly"]) in
    let _ = Sys.command (Filename.quote_command ("ocamlc") ["-c"; "parser.mli"]) in
    let _ = Sys.command (Filename.quote_command ("ocamlc") ["-c"; "lexer.ml"]) in
    let _ = Sys.command (Filename.quote_command ("ocamlc") ["-c"; "parser.ml"]) in
    let _ = Sys.command (Filename.quote_command ("ocamlc") ["-c"; "automaton.ml"]) in
    let _ = Sys.command (Filename.quote_command ("ocamlc") ["-o"; automaton_filename; "lexer.cmo"; "parser.cmo"; "automaton.cmo"]) in
    ()
  ]}
*)

(**
  Generate the lexer associated to the automaton described in the CSL (And encoded into the {!type:Ast.csl_ast}) in the form of a string that can be directly output to a [lexer.mll] file, and ready to be built by [ocamllex].
*)
val ocamllex_build_lexer : csl_ast -> string

(**
  Generate the parser associated to the automaton described in the CSL (And encoded into the {!type:Ast.csl_ast}) in the form of a string that can be directly output to a [parser.mly] file, and ready to be built by [menhir].
*)
val menhir_build_parser : csl_ast -> string

(**
  Generate the core of entry point of the program representing the automaton. It can be directly built by [ocamlc].
*)
val build_automaton_ml : csl_ast -> string