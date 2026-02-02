open Ast
open Utils

module StringSet = Set.Make(String)

type commands_args_str = {
  commands_args_str_commands: string list;
  commands_args_str_args: string list;
  commands_args_str_appendices: StringSet.t;
}

let label_excluded_characters = "-_?,;.:/!§*µù%$()"

let ocamllex_header =
  "{\n\
  open Lexing\n\
  open Parser\n\
  let next_line lexbuf =\n\
  \  let pos = lexbuf.lex_curr_p in\n\
  \  lexbuf.lex_curr_p <-\n\
  \    { pos with pos_bol = lexbuf.lex_curr_pos;\n\
  \               pos_lnum = pos.pos_lnum + 1\n\
  \    }\n\
  \n\
  \  let keywords = Hashtbl.create 10
  \n"

let ocamllex_footer =
  "\n\
  \      try\n\
  \        Hashtbl.find keywords keyword\n\
  \      with\n\
  \        Not_found -> ANYTHING\n\
  \    }\n\
  \  | _ { Format.eprintf \"Backdoor detected\\n@?\"; exit 1 }\n"

let automaton_ml_header =
  "let _ = let lexbuf = Lexing.from_channel stdin in\n\
  \n"

let automaton_ml_footer =
  "Format.eprintf \"OK\\n@?\";\n\
  exit 0"

let menhir_header =
  "%{\n\
  \  let parse_error s = Format.eprintf \"Backdoor detected (%s)\\n@?\" s; exit 1\n\
  %}\n\
  \n\
  %token EOF\n\
  %token NEWLINE\n\
  %token ARG_SEPARATOR\n\
  %token ANYTHING\n"

let menhir_other_arg_parsing_rule_header =
  "__other_arg__:\n\
  \  | ANYTHING { }\n\
  \  | ANYTHING __arg_separator__ { }\n\
  \  | ANYTHING __other_arg__ { }\n\
  \  | ANYTHING __arg_separator__ __other_arg__ { }\n"

let build_label is_case_sensitive label =
  let treated_label = String.fold_left (fun result character ->
    let result = if String.contains label_excluded_characters character == false then
      result ^ Char.escaped character
    else
      result
    in

    str_transform result ~char_src:' ' ~char_dst:'_'
  ) "" label in

  if is_case_sensitive == false then
    "LAB_" ^
      String.uppercase_ascii treated_label
  else
    "LAB_" ^
      treated_label

let ocamllex_build_keywords_declaration_string keywords is_case_sensitive =
  if is_case_sensitive == false then
    List.fold_left (fun keywords_string keyword ->
      keywords_string ^
        "  let _ = Hashtbl.add keywords \"" ^
        String.lowercase_ascii keyword ^
        "\" " ^
        build_label is_case_sensitive keyword ^
        "\n"
    ) "" keywords
  else
    List.fold_left (fun keywords_string keyword ->
      keywords_string ^
        "  let _ = Hashtbl.add keywords \"" ^
        keyword ^
        "\" " ^
        build_label is_case_sensitive keyword ^
        "\n"
    ) "" keywords

let ocamllex_keyword_search_string is_case_sensitive =
  let keyword_match_string = "  | word+ as w {\n" in

  if is_case_sensitive == false then
    keyword_match_string ^
      "      let keyword = String.lowercase_ascii w in\n"
  else
    keyword_match_string ^
      "      let keyword = w in\n"

let ocamllex_ignored_chars_string ignored_chars =
  List.fold_left (fun res c ->
    res ^ "  | '" ^ Char.escaped c ^ "' { read lexbuf }\n"
  ) "" ignored_chars

let ocamllex_arg_separator_match_string arg_separator =
  if arg_separator.arg_separator_can_be_multiple == true then
    List.fold_left (fun res c ->
      res ^
        "  | '" ^
        Char.escaped c ^
        "'+ { ARG_SEPARATOR }\n"
    ) "" arg_separator.arg_separator_chars
  else
    List.fold_left (fun res c ->
      res ^
        "  | '" ^
        Char.escaped c ^
        "' { ARG_SEPARATOR }\n"
    ) "" arg_separator.arg_separator_chars

let get_uniques_commands_and_args_form_csl_ast csl_ast =
  (* Commands *)

  let not_internal_auth_levels = List.filter (fun auth_level ->
    not (auth_level.auth_level_is_cslprocess_internal)
  ) csl_ast.csl_ast_auth_levels in

  let not_internal_commands = List.flatten (List.map (fun level ->
    let level_not_internal_commands = List.filter (fun command ->
      not (command.command_is_cslprocess_internal)
    ) level.auth_level_commands in
    
    List.map (fun command -> command.Ast.command_name) level_not_internal_commands
  ) not_internal_auth_levels) in

  let uniques_commands = if csl_ast.csl_ast_is_case_sensitive == false then
    List.sort_uniq (fun str_a str_b ->
      String.compare (String.lowercase_ascii str_a) (String.lowercase_ascii str_b)
    ) not_internal_commands
  else
    List.sort_uniq (fun str_a str_b ->
      String.compare str_a str_b
    ) not_internal_commands
  in

  (* Args *)

  let args = List.flatten (List.flatten (List.map (fun level ->
    let level_not_internal_commands = List.filter (fun command ->
      not (command.command_is_cslprocess_internal)
    ) level.auth_level_commands in

    List.map (fun command ->
      let command_args = command.command_args in

      List.filter_map (fun command_arg ->
        match command_arg.arg_value with
          | Value value -> Some value
          | Anything -> None
      ) command_args
    ) level_not_internal_commands
  ) not_internal_auth_levels)) in

  let uniques_args = if csl_ast.csl_ast_is_case_sensitive == false then
    List.sort_uniq (fun str_a str_b ->
      String.compare (String.lowercase_ascii str_a) (String.lowercase_ascii str_b)
    ) args
  else
    List.sort_uniq (fun str_a str_b ->
      String.compare str_a str_b
    ) args
  in

  (* Commands appendices *)

  let unique_appendices = List.fold_left (fun res current_auth_level ->
    List.fold_left (fun res current_command ->
      match current_command.command_appendix with
        | Some a -> StringSet.add a res
        | None -> res
    ) res current_auth_level.auth_level_commands
  ) StringSet.empty csl_ast.csl_ast_auth_levels in

  (* Assembling *)

  {
    commands_args_str_commands = uniques_commands;
    commands_args_str_args = uniques_args;
    commands_args_str_appendices = unique_appendices;
  }


let build_ocamllex_middle arg_separator_chars ignored_chars =
  let arg_separator_chars_str = List.fold_left (fun res c ->
    res ^ " '" ^ Char.escaped c ^ "'"
  ) "" arg_separator_chars in

  let ignored_chars_str = List.fold_left (fun res c ->
    res ^ " '" ^ Char.escaped c ^ "'"
  ) "" ignored_chars in

  let str_begin =
    "\
    }\n\n\
    let newline = '\\n' | \"\\r\\n\"\n\
    let word = [^'\\n'"
  in
    
  let str_end =
    "]\n\
    \n\
    rule read =\n\
    \  parse\n\
    \  | newline { NEWLINE }\n\
    \  | eof { EOF }\n"
  in

  str_begin ^ arg_separator_chars_str ^ ignored_chars_str ^ str_end

let ocamllex_build_lexer csl_ast =
  let case_sensitivity = csl_ast.csl_ast_is_case_sensitive in
  let commands_and_args_strings = get_uniques_commands_and_args_form_csl_ast csl_ast in

  let appendices_strings_set = commands_and_args_strings.commands_args_str_appendices in

  let commands_strings = commands_and_args_strings.commands_args_str_commands in
  let args_strings = commands_and_args_strings.commands_args_str_args in
  let appendices_strings = StringSet.to_list appendices_strings_set in

  let commands_tokens_declarations_string = ocamllex_build_keywords_declaration_string commands_strings case_sensitivity in
  let args_tokens_declarations_string = ocamllex_build_keywords_declaration_string args_strings case_sensitivity in
  let appendices_tokens_declarations_string = ocamllex_build_keywords_declaration_string appendices_strings case_sensitivity in

  let ignored_chars = csl_ast.csl_ast_ignored_chars in

  (* Ocamllex build *)

  ocamllex_header ^
    commands_tokens_declarations_string ^
    args_tokens_declarations_string ^
    appendices_tokens_declarations_string ^
    build_ocamllex_middle csl_ast.csl_ast_arg_separator.arg_separator_chars ignored_chars ^
    ocamllex_ignored_chars_string ignored_chars ^
    ocamllex_arg_separator_match_string csl_ast.csl_ast_arg_separator ^
    ocamllex_keyword_search_string csl_ast.csl_ast_is_case_sensitive ^
    ocamllex_footer

let menhir_build_token_declaration_string is_case_sensitive labels =
  let (result, _) = List.fold_left (fun (declarations_string, already_defined_tokens) current_command_string ->
    let token = build_label is_case_sensitive current_command_string in

    match StringSet.exists (String.equal token) already_defined_tokens with
      | false ->
          let new_declaration_string = declarations_string ^
            "%token " ^
            token ^
            "\n"
          in

          let new_already_defined_tokens = StringSet.add token already_defined_tokens in

          (new_declaration_string, new_already_defined_tokens)
      | true ->
          (declarations_string, already_defined_tokens)
  ) ("", StringSet.empty) labels in

  result

let menhir_build_start_level_declaration_string csl_ast =
  let start_level = get_auth_level_by_id csl_ast csl_ast.csl_ast_initial_auth_level_id in
  let start_level_name = start_level.auth_level_name in

  "%start " ^
    start_level_name ^
    "\n"

let menhir_build_types_string csl_ast =
  let auth_levels_ids_and_names = get_auth_levels_ids_and_names csl_ast in

  let auth_levels = List.map (fun (_, auth_level) ->
    auth_level
  ) auth_levels_ids_and_names in

  let filtered_auth_levels = List.filter (fun auth_level ->
    (String.equal auth_level "__OTHER_COMMAND__" == false) && (String.equal auth_level "__VOID_AUTH_LEVEL__" == false)
  ) auth_levels in

  let result = "%type <unit> __arg_separator__\n%type <unit> __other_arg__\n%type <unit> __newline__\n" in

  List.fold_left (fun result current_auth_level ->
    result ^ "%type <unit> " ^ current_auth_level ^ "\n"
  ) result filtered_auth_levels

let menhir_build_levels_transitions_declaration csl_ast =
  let not_internal_levels = List.filter (fun level ->
    not (level.auth_level_is_cslprocess_internal)
  ) csl_ast.csl_ast_auth_levels in

  List.fold_left (fun levels_transitions_declarations current_level ->
    let current_level_name = current_level.auth_level_name in

    let not_internal_commands = List.filter (fun command ->
      not (command.command_is_cslprocess_internal)
    ) current_level.auth_level_commands in

    let transitions = List.fold_left (fun commands_transitions_declarations current_command ->
      let current_command_label = build_label csl_ast.csl_ast_is_case_sensitive current_command.command_name in

      let args_transitions = List.fold_left (fun args_transitions_declarations current_arg ->
        let arg_value = current_arg.arg_value in
        
        let target_state_id = current_arg.arg_auth_level_target_id in
        let target_state = Ast.get_auth_level_by_id csl_ast target_state_id in
        let target_state_name = target_state.auth_level_name in

        let arg_label = match arg_value with
          | Anything -> "__other_arg__"
          | Value value -> build_label csl_ast.csl_ast_is_case_sensitive value
        in

        match current_command.command_appendix with
        | Some appendix ->
            let appendix_label = build_label csl_ast.csl_ast_is_case_sensitive appendix in

            args_transitions_declarations ^
              "  | " ^
              current_command_label ^
              " __arg_separator__ " ^
              arg_label ^
              " __arg_separator__ " ^
              appendix_label ^
              " __newline__ " ^
              target_state_name ^
              " { }\n"
        | None ->
            args_transitions_declarations ^
              "  | " ^
              current_command_label ^
              " __arg_separator__ " ^
              arg_label ^
              " __newline__ " ^
              target_state_name ^
              " { }\n"
      ) "" current_command.command_args in

      commands_transitions_declarations ^
        "  | " ^
        current_command_label ^
        " __newline__ "^
        current_level_name ^
        " { }\n" ^
        args_transitions ^
        "  | " ^
        current_command_label ^
        " __arg_separator__ __newline__ "^
        current_level_name ^
        " { }\n" ^
        args_transitions
    ) "" not_internal_commands in

    levels_transitions_declarations ^
      current_level_name ^
      ":\n  | EOF { }\n" ^
      transitions ^
      "  ;\n\n"
  ) "" not_internal_levels

let menhir_build_other_args_rule commands args is_case_sensitive =
  let commands_tokens = List.map (fun cmd ->
    build_label is_case_sensitive cmd
  ) commands in

  let args_tokens = List.map (fun arg ->
    build_label is_case_sensitive arg
  ) args in

  let tokens = commands_tokens @ args_tokens in

  let rules = List.map (fun token ->
    "  | " ^ token ^ " { }\n\
    \  | " ^ token ^ " __arg_separator__ { }\n\
    \  | " ^ token ^ " __other_arg__ { }\n\
    \  | " ^ token ^ " __arg_separator__ __other_arg__ { }\n"
  ) tokens in

  let rules_str = List.fold_left (fun rules rule ->
    rules ^ rule
  ) "" rules in

  menhir_other_arg_parsing_rule_header ^ rules_str ^ "  ;\n\n"

let menhir_build_newline_rule csl_ast =
  if csl_ast.csl_ast_ignore_empty_commands == true then
    "__newline__:\n\
    \  | NEWLINE { }\n\
    \  | NEWLINE __newline__ { }\n\
    \  ;\n\n"
  else
    "__newline__:\n\
    \  | NEWLINE { }\n\
    \  ;\n\n"

let menhir_build_arg_separator_rule csl_ast =
  if csl_ast.csl_ast_arg_separator.arg_separator_can_be_multiple == true then
    "__arg_separator__:\n\
    \  | ARG_SEPARATOR { }\n\
    \  | ARG_SEPARATOR __arg_separator__ { }\n\
    \  ;\n\n"
  else
    "__arg_separator__:\n\
    \  | ARG_SEPARATOR { }\n\
    \  ;\n\n"

let menhir_build_parser csl_ast =
  let commands_and_args_str = get_uniques_commands_and_args_form_csl_ast csl_ast in
  let commands_and_args_str_appendices_list = StringSet.to_list commands_and_args_str.commands_args_str_appendices in

  let merged_commands_and_args_str =
    commands_and_args_str.commands_args_str_commands @
    commands_and_args_str.commands_args_str_args @
    commands_and_args_str_appendices_list
  in

  let token_declarations = menhir_build_token_declaration_string csl_ast.csl_ast_is_case_sensitive merged_commands_and_args_str in
  let start_level_declaration = menhir_build_start_level_declaration_string csl_ast in
  let auth_level_types_declaration = menhir_build_types_string csl_ast in
  let levels_transitions_declaration = menhir_build_levels_transitions_declaration csl_ast in

  let other_args_parsing_rule = menhir_build_other_args_rule commands_and_args_str.commands_args_str_commands commands_and_args_str.commands_args_str_args false in
  let newline_parsing_rule = menhir_build_newline_rule csl_ast in
  let arg_separator_parsing_rule = menhir_build_arg_separator_rule csl_ast in

  menhir_header ^
    token_declarations ^
    start_level_declaration ^
    auth_level_types_declaration ^
    "%%\n\n" ^
    arg_separator_parsing_rule ^
    other_args_parsing_rule ^
    newline_parsing_rule ^
    levels_transitions_declaration

let build_automaton_ml csl_ast =
  automaton_ml_header ^
    "Parser." ^ get_initial_auth_level_name csl_ast ^ " Lexer.read lexbuf;\n" ^
    automaton_ml_footer