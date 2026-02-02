(** Stright-forward module to build a very primal AST, before computing the real {!module:Ast}. {b This module should not be used directly, please use {!module:Ast} instead of, unless you know what you are doing !!!} *)

val current_line : int ref

type parser_arg_separator_definition = {
  parser_arg_separator_definition_chars: char list;
  parser_arg_separator_definition_can_be_multiple: bool;
}

type parser_arg_definition = {
  parser_arg_definition_value: string;
  parser_arg_definition_target_level_name: string;
  parser_arg_definition_is_important: bool;
}

type parser_command_definition = {
  parser_command_definition_name: string;
  parser_command_definition_args_definitions: parser_arg_definition list;
  parser_command_definition_appendix: string option;
}

type parser_level_definition = {
  parser_level_definition_name: string;
  parser_level_definition_commands_definitions: parser_command_definition list;
}

type parser_syscall_definition = {
  parser_syscall_definition_name: string;
  parser_syscall_definition_args: string list;
}

type parser_authorized_syscalls = {
  parser_authorized_syscalls_command: string;
  parser_authorized_syscalls_syscalls_names: string list;
}

type parser_syscalls_definition = {
  parser_syscalls_definition_accepted: parser_syscall_definition list;
  parser_syscalls_definition_refused: parser_syscall_definition list;
  parser_syscalls_definition_ignored: parser_syscall_definition list;
  parser_syscalls_definition_authorized_syscalls: parser_authorized_syscalls list;
}

type parser_custom_seeds_definition = {
  parser_custom_seeds_definition_associated_commands: string list;
  parser_custom_seeds_definition_seeds: string list;
}

type parser_adversarial_sequences_generation =
| Full
| Minimal

type parser_syscalls_getting_mode =
| Per_Commands
| One_Shot

type parser_csl_parameters_elements =
| Case_Sensitivity of bool
| Arg_Separator of parser_arg_separator_definition
| Initial_Level of string
| Consider_Other_Commands of bool
| Adversarial_Sequences_Generation of parser_adversarial_sequences_generation
| Ignore_Empty_Commands of bool
| Ignored_Chars of char list
| Commands_Prefix of string
| Adversarial_Sequences_Ending of string
| Split_Adversarial_Sequences_Args of bool
| Syscalls_Getting_Mode of parser_syscalls_getting_mode

type parser_csl = {
  parser_csl_parameters: parser_csl_parameters_elements list;
  parser_csl_levels_definitions: parser_level_definition list;
  parser_csl_syscalls_option: parser_syscalls_definition option;
  parser_csl_custom_seeds_list_option: parser_custom_seeds_definition list option;
}

val parser_arg_separator_definition_builder : char list -> bool -> parser_arg_separator_definition
val parser_arg_definition_builder : string -> string -> bool -> parser_arg_definition
val parser_command_definition_builder : string -> parser_arg_definition list -> string option -> parser_command_definition
val parser_level_definition_builder : string -> parser_command_definition list -> parser_level_definition
val parser_syscall_definition_builder : string -> string list -> parser_syscall_definition
val parser_authorized_syscalls_builder : string -> string list -> parser_authorized_syscalls
val parser_syscalls_definition_builder : parser_syscall_definition list -> parser_syscall_definition list -> parser_syscall_definition list -> parser_authorized_syscalls list -> parser_syscalls_definition
val parser_custom_seeds_definition_builder: string list -> string list -> parser_custom_seeds_definition
val parser_csl_builder : parser_csl_parameters_elements list -> parser_level_definition list -> parser_syscalls_definition option -> parser_custom_seeds_definition list option -> parser_csl