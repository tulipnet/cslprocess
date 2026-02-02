open Ast
open Exceptions

val generate_seeds_for_all_commands : csl_ast -> (int * string list option * bool) list
val generate_seeds_for_adversarial_sequences_with_precedence_relation : csl_ast -> (int list * string) list -> (int list * string list) list