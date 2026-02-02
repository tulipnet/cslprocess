open Ast
open Exceptions
open Utils

let read_resource resource_name =
  let self_binary_path = Unix.readlink "/proc/self/exe" in

  let root =
    if String.starts_with ~prefix:"/usr/local" self_binary_path then
      "/usr/local/share/cslprocess_v2/"
    else
      Filename.dirname (Filename.dirname self_binary_path ^ "/../resources")
  in

  let resource_path = root ^ "/resources/" ^ resource_name in
  let resource_fd = open_in resource_path in
  let result = In_channel.input_all resource_fd in

  close_in resource_fd;

  result

let get_syscalls_sh_header =
  "#!/bin/bash\n\
  \n\
  REPERTOIRE_ENTREES=\"$1\"\n\
  REPERTOIRE_SORTIE=\"$2\"\n\
  EXECUTABLE=\"$3\"\n\
  BASE_DIRECTORY=\"$4\"\n\
  \n\
  if [ \"x${CBD_PRELOAD}\" != \"x\" ]\n\
  then\n\
  \  export _LD_PRELOAD=\"${CBD_PRELOAD}\"\n\
  fi\n\
  \n\
  if [ \"x$REPERTOIRE_ENTREES\" != \"x\" ] && [ \"x$REPERTOIRE_SORTIE\" != \"x\" ] && [ \"x$EXECUTABLE\" != \"x\" ]\n\
  then\n\
  \  if [ \"x$BASE_DIRECTORY\" == \"x\" ]\n\
  \  then\n\
  \    BASE_DIRECTORY=.\n\
  \  fi\n\
  \  \n\
  \  mkdir -p \"$REPERTOIRE_SORTIE\"\n\
  \  mkdir \"$REPERTOIRE_SORTIE\"/full\n\
  \  \n\
  \  for FIC in `find $REPERTOIRE_ENTREES -type f`\n\
  \  do\n\
  \    NOM_DU_FICHIER=`echo $FIC | sed -re \"s?.*/??g\"`\n"

let get_syscalls_sh_footer =
  "\  done\n\
  else\n\
  \   echo \"ERREUR : Il manque l'argument\"\n\
  fi"

let syscall_monitor_ml_header =
  "exception FileNotFoundException of string\n\
  exception CardinalException of string\n\
  \n"

let syscall_monitor_ml_footer = read_resource "syscall_monitor_ml_footer.res"

let generate_get_syscalls_sh csl_ast =
  let syscalls = get_syscalls csl_ast in
  let command_to_run_args = match get_syscalls_command_to_run_args csl_ast with
    | None -> raise NoDeclaredSyscalls
    | Some s -> s
  in

  let strace_command = match csl_ast.csl_ast_syscalls_getting_mode with
    | Per_Commands ->
        "\n    timeout 0.25s buffered_pipe_writer_strace \"$FIC\" -s 1000 -f -e trace=read," ^
        String.concat "," syscalls ^
        " -- $EXECUTABLE " ^
        command_to_run_args ^
        " 2> \"$REPERTOIRE_SORTIE\"/\"$NOM_DU_FICHIER\"\n"
    | One_Shot ->
        "\n    timeout 0.25s strace -s 1000 -E LD_PRELOAD=$_LD_PRELOAD -f -e trace=read," ^
        String.concat "," syscalls ^
        " $EXECUTABLE " ^
        command_to_run_args ^
        " < \"$FIC\" 2> \"$REPERTOIRE_SORTIE\"/\"$NOM_DU_FICHIER\"\n"
  in

  let unfiltered_strace_command = match csl_ast.csl_ast_syscalls_getting_mode with
    | Per_Commands ->
        "\n    timeout 0.25s buffered_pipe_writer_strace \"$FIC\" -s 1000 -f -- $EXECUTABLE " ^
        command_to_run_args ^
        " 2> \"$REPERTOIRE_SORTIE\"/full/\"$NOM_DU_FICHIER\"\n"
    | One_Shot ->
        "\n    timeout 0.25s strace -s 1000 -E LD_PRELOAD=$_LD_PRELOAD -f $EXECUTABLE " ^
        command_to_run_args ^
        " < \"$FIC\" 2> \"$REPERTOIRE_SORTIE\"/full/\"$NOM_DU_FICHIER\"\n"
  in

  let post_processing_strace_files =
    "\n\
     \    sed -re \"s/\\[pid *[0-9]*\\] //g\" -i \"$REPERTOIRE_SORTIE\"/\"$NOM_DU_FICHIER\"\n\
     \    sed -re \"s/\\[pid *[0-9]*\\] //g\" -i \"$REPERTOIRE_SORTIE\"/full/\"$NOM_DU_FICHIER\"\n"
  in

  get_syscalls_sh_header ^ strace_command ^ unfiltered_strace_command ^ post_processing_strace_files ^ get_syscalls_sh_footer

let escape_regex_str regex_str =
  let escaped_plus = Str.global_replace (Str.regexp "\\+") "\\\\\\+" regex_str in
  let espaced_quotes = Str.global_replace (Str.regexp "\\\"") "\"" escaped_plus in

  espaced_quotes

let syscall_to_regexp syscall =
  "Str.regexp (\"" ^ escape_regex_str syscall ^ "\")"

let escape_str str =
  "\"" ^ str ^ "\""

let bool2string = function
  | true -> "true"
  | false -> "false"

let char2string c =
  String.make 1 c

let generate_syscall_monitor_ml csl_ast =
  let first_arg_separator = List.nth csl_ast.csl_ast_arg_separator.arg_separator_chars 0 in

  let refused_syscalls = get_syscalls_refused_as_str csl_ast in
  let ignored_syscalls = get_syscalls_ignored_as_str csl_ast in
  let accepted_syscalls = get_syscalls_accepted_as_str csl_ast in
  let syscalls_names = get_syscalls csl_ast in
  let commands_are_case_sensitive = csl_ast.csl_ast_is_case_sensitive in
  let arg_separator = first_arg_separator in
  let ignore_empty_commands = csl_ast.csl_ast_ignore_empty_commands in

  let refused_syscalls_declarations = List.map syscall_to_regexp refused_syscalls in
  let ignored_syscalls_declarations = List.map syscall_to_regexp ignored_syscalls in
  let accepted_syscalls_declarations = List.map syscall_to_regexp accepted_syscalls in
  let syscalls_names_declarations = List.map escape_str syscalls_names in
  let commands_are_case_sensitive_declaration = bool2string commands_are_case_sensitive in
  let arg_separator_declaration = char2string arg_separator in
  let ignore_empty_commands_declaration = bool2string ignore_empty_commands in

  let commands_prefix_declaration = match csl_ast.csl_ast_commands_prefix with
    | None -> "None"
    | Some p -> "Some \"" ^ p ^ "\""
  in

  let refused_syscalls_declaration_str = str_join ";" refused_syscalls_declarations in
  let ignored_syscalls_declaration_str = str_join ";" ignored_syscalls_declarations in
  let accepted_syscalls_declaration_str = str_join ";" accepted_syscalls_declarations in
  let syscalls_names_str = str_join ";" syscalls_names_declarations in

  let authorized_syscalls_declaration = get_authorized_syscalls_as_hashtabl_definition_string csl_ast in

  syscall_monitor_ml_header ^
    "let refused_syscalls = [" ^ refused_syscalls_declaration_str ^ "]\n" ^
    "let ignored_syscalls = [" ^ ignored_syscalls_declaration_str ^ "]\n" ^
    "let accepted_syscalls = [" ^ accepted_syscalls_declaration_str ^ "]\n" ^
    "let syscall_names = [\"read\";" ^ syscalls_names_str ^ "]\n" ^
    "let commands_are_case_sensitive = " ^ commands_are_case_sensitive_declaration ^ "\n" ^
    "let arg_separator = '" ^ arg_separator_declaration ^ "'\n" ^
    "let ignore_empty_commands = " ^ ignore_empty_commands_declaration ^ "\n" ^
    "let commands_prefix = " ^ commands_prefix_declaration ^ "\n\n" ^
    authorized_syscalls_declaration ^ "\n" ^
    syscall_monitor_ml_footer
