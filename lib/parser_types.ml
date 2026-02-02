let current_line = ref 1

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

let parser_arg_separator_definition_builder arg_separator can_be_multiple = {
  parser_arg_separator_definition_chars = arg_separator;
  parser_arg_separator_definition_can_be_multiple = can_be_multiple;
}

let parser_arg_definition_builder value target_level_name is_important = {
  parser_arg_definition_value = value;
  parser_arg_definition_target_level_name = target_level_name;
  parser_arg_definition_is_important = is_important;
}

let parser_command_definition_builder name args_definitions appendix_option = {
  parser_command_definition_name = name;
  parser_command_definition_args_definitions = args_definitions;
  parser_command_definition_appendix = appendix_option;
}

let parser_level_definition_builder name commands_definitions = {
  parser_level_definition_name = name;
  parser_level_definition_commands_definitions = commands_definitions;
}

let parser_syscall_definition_builder name args = {
  parser_syscall_definition_name = name;
  parser_syscall_definition_args = args;
}

let parser_authorized_syscalls_builder command_name syscalls_names = {
  parser_authorized_syscalls_command = command_name;
  parser_authorized_syscalls_syscalls_names = syscalls_names;
}

let parser_syscalls_definition_builder accepted_syscalls refused_syscalls ignored_syscalls authorized_syscalls = {
  parser_syscalls_definition_accepted = accepted_syscalls;
  parser_syscalls_definition_refused = refused_syscalls;
  parser_syscalls_definition_ignored = ignored_syscalls;
  parser_syscalls_definition_authorized_syscalls = authorized_syscalls;
}

let parser_custom_seeds_definition_builder commands seeds = {
  parser_custom_seeds_definition_associated_commands = commands;
  parser_custom_seeds_definition_seeds = seeds;
}

let parser_csl_builder csl_parameters levels_definitions syscalls_definitions_option custom_seeds_definition_list_option = {
  parser_csl_parameters = csl_parameters;
  parser_csl_levels_definitions = levels_definitions;
  parser_csl_syscalls_option = syscalls_definitions_option;
  parser_csl_custom_seeds_list_option = custom_seeds_definition_list_option;
}