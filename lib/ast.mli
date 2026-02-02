open Parser_types
open Exceptions

(** Kernel of CSLProcess: Embeds the generated AST from the CSL specification, and functions to compute results on it. *)

(** Type of an argument *)
type arg_value =
  | Anything (** Means anything but already declared values *)
  | Value of string (** Specific value *)


(** An argument itself *)
type arg = {
  arg_auth_level_target_id: int; (** Targeted authentication level *)
  arg_value: arg_value; (** Value of the argument *)
  arg_is_important: bool; (** Determines if the argument is explicitely tagged as important in the CSL specification or not. *)
}

(** Describe how to split a command and its arguments *)
type arg_separator = {
  arg_separator_chars: char list; (** List of possible separators *)
  arg_separator_can_be_multiple: bool; (** [true]: The argument separator can be specified multiple times (Ex: ["USER    toto"] is allowed if [arg_separator_can_be_multiple = true], not if [arg_separator_can_be_multiple = false]. *)
}

(** Describe a single command *)
type command = {
  command_name: string;
  command_args: arg list;
  command_is_cslprocess_internal: bool; (** Internal usage, determines if the command is an internal CSLProcess one (For example, to generate general cases for commands in adversarial sequences). *)
  command_appendix: string option; (** A constant appendix after a command and its arguments, for example, in HTTP, if [command_appendix = "HTTP/1.1"], a possible adversarial command will be ["GET / HTTP/1.1"]. It permits to preserve the appendix outside the wildcarded parts of the adversarial sequences. *)
}

(** Describe an authentication level *)
type auth_level = {
  auth_level_id: int;
  auth_level_name: string;
  auth_level_commands: command list;
  auth_level_is_cslprocess_internal: bool; (** Internal usage, determines if the authentication level is an internal CSLProcess one (For example, to generate general cases for commands in adversarial sequences). *)
}

(** Describe a system call (authorized, refused, ignored in the CSL specification) *)
type syscall_definition = {
  syscall_definition_name: string; (** Name of the syscall ([read], [write], etc.) *)
  syscall_definition_args: string list; (** List of the system call arguments (Ex: [write(1, "Coucou\n", 5)] => [["1"; "Coucou\n"; 5]]) *)
}

(** Describe authorized system calls for a command *)
type authorized_syscalls = {
  authorized_syscalls_command_name: string;
  authorized_syscalls_syscalls_names: string list; (** List of the authorized syscalls names (Ex: [["read"; "write"; "pipe"]]) *)
}

(** Definition of the syscall part of the CSL in the AST *)
type syscalls_definition = {
  syscalls_definition_command_to_run_args: string;
  syscalls_definition_accepted: syscall_definition list;
  syscalls_definition_refused: syscall_definition list;
  syscalls_definition_ignored: syscall_definition list;
  syscalls_definition_authorized_syscalls: authorized_syscalls list;
}

type custom_seeds_definition = {
  custom_seeds_definition_associated_commands: string list;
  custom_seeds_definition_seeds: string list;
}

(** Describe how to generate adversarial sequences *)
type adversarial_sequences_generation =
  | Full (** All declared commands in the CSL specification are used in adversarial sequences *)
  | Minimal (** Only important commands are used in adversarial sequences. For an arg -> level transition, no important command is declared, the first unimportant one is used *)

(** Describe how to get system class when exercising the target against a generated adversarial sequence *)
type syscalls_getting_mode =
  | Per_Commands (** Each command is sent one by one, by using buffered_pipe_writer to the target *)
  | One_Shot (** The whole command sequence is sent in a one shot to the target *)

(** The main type of cslprocess. Contains the whole content of the CSL specification after parsing and arrangement. *)
type csl_ast = {
  csl_ast_is_case_sensitive: bool; (** Are the commands and arguments case sensitive? *)
  csl_ast_arg_separator: arg_separator;
  csl_ast_initial_auth_level_id: int;
  csl_ast_adversarial_sequences_generation_mode: adversarial_sequences_generation;
  csl_ast_ignore_empty_commands: bool; (** Does syscall_monitor ignores empty commands? *)
  csl_ast_auth_levels: auth_level list;
  csl_ast_syscalls: syscalls_definition option;
  csl_ast_ignored_chars: char list; (** Ignored characters in the generated automaton *)
  csl_ast_commands_prefix: string option; (** Prefix to add to commands (Example: With IMAP, a prefix should be added before each command) *)
  csl_ast_adversarial_sequences_ending: string option; (** Suffix to add after each adversarial sequences. By default, is ['\n']. *)
  csl_ast_split_adversarial_sequences_args: bool; (** When command arguments contains some argument separators, if true, splits complex args like ["milhouse lisa"] to ["*-{milhouse} *-{lisa}"], instead of ["*-{milhouse lisa}"]. *)
  csl_ast_syscalls_getting_mode: syscalls_getting_mode;
  csl_ast_custom_seeds_definitions: custom_seeds_definition list option;
}

(**
  Get an {!type:auth_level} by looking its id.
  @raise Failure If the id does not exist
  @returns The associated authentication level
*)
val get_auth_level_by_id : csl_ast -> int -> auth_level

(**
  Get a list of [(int * string)] containing an auth level ID with its name. More precisely, contains tuples in the form of [(auth_level.auth_level_id, auth_level.auth_level_name)].
*)
val get_auth_levels_ids_and_names : csl_ast -> (int * string) list

(**
  Get a list of all commands names, and for each command, if it takes an argument or not.
*)
val get_commands_and_if_they_take_args : csl_ast -> (string * bool) list

(**
  Get all commands used for adversarial sequences generation (See {!type:adversarial_sequences_generation}) in a form of an hash table. The key represents the command (In form of stared command, with its associated command node in the AST), and the value, all {b authorized transitions} regarding the specification.

  For example, if for the authentication level 0, the reflexive command ["NOOP"] (without argument) is allowed, one element will be [(("NOOP"), [(0, 0)])].

  If the command ["USER"] takes an argument (For example, ["milhouse"], that goes from the authentication level 0 to 1), one element will be [("USER milhouse", [(0, 1)])], and another [("USER *-{milhouse}", [(0, 0)])].

  In definitive, the goal of this function is to generate atoms for the adversarial sequence generator.
*)
val get_stared_commands_and_commands_with_args_from_and_to_auth_level_ids : csl_ast -> (string * command, (int * int) list) Hashtbl.t

(**
  Get the highest authentication level ID.
*)
val get_max_auth_level_id : csl_ast -> int

(**
  [get_commands_and_target_auth_levels_ids_for_an_auth_level_id csl_ast auth_level_id are_adversarial] returns all wilcarded commands from [auth_level_id], with their target authentication levels ids and the associate command node.

  @returns

  If [are_adversarial == true], then adversarial commands for the authentication level [auth_level_id] associated to the destination authentication levels.

  Else, it returns the non-adversarial commands from the level [auth_level] with its destination authentication levels.
*)
val get_commands_and_target_auth_levels_ids_for_an_auth_level_id : csl_ast -> int -> bool -> (string * command * int list) list

(**
  Get declared system calls names in the [accepted:], [refused:] and [ignored:] sections of the CSL specification (Example: [["read"; "write"]]).
*)
val get_syscalls : csl_ast -> string list

(**
  Get arguments passed to the target when getting system calls. Are passed as parameter to {!val:build_csl_ast_from_parsed_csl}.
*)
val get_syscalls_command_to_run_args : csl_ast -> string option

(**
  Build a {!type:csl_ast} from a previously parsed CSL specification, and args to pass to the target to test it.

  @raises Exceptions.LevelNotFound If the [initial_level] clause of the CSL specification points to an unknown {!type:auth_level}.
*)
val build_csl_ast_from_parsed_csl : parser_csl -> string -> csl_ast

(**
  Print on the error output {i stderr} an human-readable textual representation of the {!type:csl_ast}.
*)
val print_csl_ast : csl_ast -> unit

(**
  Get refused system calls patterns (Declared in [refused:] in the CSL specification) in form of OCaml-readable regular expressions.
*)
val get_syscalls_refused_as_str : csl_ast -> string list

(**
  Get ignored system calls patterns (Declared in [ignored:] in the CSL specification) in form of OCaml-readable regular expressions.
*)
val get_syscalls_ignored_as_str : csl_ast -> string list

(**
  Get accepted system calls patterns (Declared in [accepted:] in the CSL specification) in form of OCaml-readable regular expressions.
*)
val get_syscalls_accepted_as_str : csl_ast -> string list

(**
  Get the initial authentication level's name of the {!type:csl_ast}.
*)
val get_initial_auth_level_name : csl_ast -> string

(**
  Get all the {b non-adverarial} transitions (Depending on {!type:adversarial_sequences_generation}) to wildcarded commands. Relies on {!val:get_stared_commands_and_commands_with_args_from_and_to_auth_level_ids}.
*)
val get_auth_levels_transitions_to_stared_commands : csl_ast -> ((int * int), string list) Hashtbl.t

(**
  Get all authorized system calls for every declared commands in the [authorized_syscalls:] part of the CSL specification, to declare an OCaml [Hashtabl] hash table. Used in {!module:Syscall_monitor}.
*)
val get_authorized_syscalls_as_hashtabl_definition_string : csl_ast -> string