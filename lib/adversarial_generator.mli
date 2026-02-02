open Ast

(** Module embedding functions related to the generation of the adversarial sequences related to the CSL specification. *)

(**
  Get all wildcarded commands ({b Adversarial} and {b non-adversarial}) used to generate the adversarial sequences, associated with an ID and the command AST node
*)
val generate_all_commands : csl_ast -> (int * string * command) list

(**
  [generate_adversarial_sequences_and_get_precedence_relation csl_ast max_depth] returns the generated adversarial sequences of maximal depth of [max_depth] associated to their commands ID.

  For example, if an adversarial command ["USER milhouse"] has the ID 1, ad [max_depth = 2], a tuple in the returned list will be [([1; 1; -1], "USER milhouse\nUSER milhouse\n")]. The remaining [-1] at the end is used by the algorithm, and correspond to the final state of the complementary automaton generated for the adversarial sequences generation.
*)
val generate_adversarial_sequences_and_get_precedence_relation : csl_ast -> int -> (int list * string) list