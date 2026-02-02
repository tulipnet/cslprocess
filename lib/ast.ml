open Parser_types
open Exceptions
open Utils

type arg_value =
  | Anything
  | Value of string

type arg = {
  arg_auth_level_target_id: int;
  arg_value: arg_value;
  arg_is_important: bool;
}

type arg_separator = {
  arg_separator_chars: char list;
  arg_separator_can_be_multiple: bool;
}

type command = {
  command_name: string;
  command_args: arg list;
  command_is_cslprocess_internal: bool;
  command_appendix: string option;
}

type auth_level = {
  auth_level_id: int;
  auth_level_name: string;
  auth_level_commands: command list;
  auth_level_is_cslprocess_internal: bool;
}

type syscall_definition = {
  syscall_definition_name: string;
  syscall_definition_args: string list;
}

type authorized_syscalls = {
  authorized_syscalls_command_name: string;
  authorized_syscalls_syscalls_names: string list;
}

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

type adversarial_sequences_generation =
  | Full
  | Minimal

type syscalls_getting_mode =
  | Per_Commands
  | One_Shot

type csl_ast = {
  csl_ast_is_case_sensitive: bool;
  csl_ast_arg_separator: arg_separator;
  csl_ast_initial_auth_level_id: int;
  csl_ast_adversarial_sequences_generation_mode: adversarial_sequences_generation;
  csl_ast_ignore_empty_commands: bool;
  csl_ast_auth_levels: auth_level list;
  csl_ast_syscalls: syscalls_definition option;
  csl_ast_ignored_chars: char list;
  csl_ast_commands_prefix: string option;
  csl_ast_adversarial_sequences_ending: string option;
  csl_ast_split_adversarial_sequences_args: bool;
  csl_ast_syscalls_getting_mode: syscalls_getting_mode;
  csl_ast_custom_seeds_definitions: custom_seeds_definition list option;
}

type csl_ast_parameters = {
  mutable csl_ast_parameters_is_case_sensitive: bool;
  mutable csl_ast_parameters_arg_separator: arg_separator;
  mutable csl_ast_parameters_initial_auth_level_name: string;
  mutable csl_ast_parameters_consider_other_commands: bool;
  mutable csl_ast_parameters_adversarial_sequences_generation: adversarial_sequences_generation;
  mutable csl_ast_parameters_ignore_empty_commands: bool;
  mutable csl_ast_parameters_ignored_chars: char list;
  mutable csl_ast_parameters_commands_prefix: string option;
  mutable csl_ast_parameters_adversarial_sequences_ending: string option;
  mutable csl_ast_parameters_split_adversarial_sequence_args: bool;
  mutable csl_ast_parameters_syscalls_getting_mode: syscalls_getting_mode;
}

let get_auth_levels_from_parsed_auth_levels parsed_auth_levels =
  List.map (fun parsed_auth_level ->
    parsed_auth_level.Parser_types.parser_level_definition_name)
  parsed_auth_levels

let get_level_id auth_levels auth_level_name =
  let auth_level_id_option = List.find_index (fun current_auth_level_name ->
    String.equal current_auth_level_name auth_level_name) auth_levels
  in

  match auth_level_id_option with
    | Some value -> value
    | None -> -1

let get_auth_level_by_id csl_ast id =
  let filtered_auth_levels = List.filter (fun auth_level ->
    auth_level.auth_level_id == id
  ) csl_ast.csl_ast_auth_levels in

  List.nth filtered_auth_levels 0

let build_csl_ast_args parsed_csl_args_definitions auth_levels_names current_auth_level_id =
  List.map (fun parsed_csl_arg_definition ->
    let target_auth_level_name = parsed_csl_arg_definition.Parser_types.parser_arg_definition_target_level_name in

    let target_auth_level_id = match target_auth_level_name with
      | "" -> current_auth_level_id
      | _ -> get_level_id auth_levels_names target_auth_level_name
    in

    let parsed_arg_value = parsed_csl_arg_definition.Parser_types.parser_arg_definition_value in

    let arg_value = match parsed_arg_value with
      | "_" -> Anything
      | _ -> Value parsed_arg_value
    in

    let arg_is_important = parsed_csl_arg_definition.parser_arg_definition_is_important in

    if (target_auth_level_id != -1) then
      {
        arg_auth_level_target_id = target_auth_level_id;
        arg_value = arg_value;
        arg_is_important = arg_is_important;
      }
    else
      raise (LevelNotFound ("build_csl_ast_args -> The privilege level \"" ^ target_auth_level_name ^ "\" does not exist."));
  ) parsed_csl_args_definitions

let build_csl_ast_commands parsed_csl_commands_definitions auth_levels_names current_auth_level_id =
  List.map (fun parsed_csl_command_definition ->
    let command_name = parsed_csl_command_definition.Parser_types.parser_command_definition_name in
    let parsed_csl_args_definitions = parsed_csl_command_definition.Parser_types.parser_command_definition_args_definitions in

    let args_csl_ast = build_csl_ast_args parsed_csl_args_definitions auth_levels_names current_auth_level_id in

    {
      command_name = command_name;
      command_args = args_csl_ast;
      command_is_cslprocess_internal = false;
      command_appendix = parsed_csl_command_definition.Parser_types.parser_command_definition_appendix;
    }
  ) parsed_csl_commands_definitions

let build_csl_ast_auth_levels parsed_csl_levels_definitions auth_levels_names =
  List.map (fun auth_level_definition ->
    let current_level_name = auth_level_definition.Parser_types.parser_level_definition_name in

    let id = get_level_id auth_levels_names current_level_name in

    let current_level_commands_definitions = auth_level_definition.Parser_types.parser_level_definition_commands_definitions in

    if (id != -1) then
      {
        auth_level_id = id;
        auth_level_name = current_level_name;
        auth_level_commands = build_csl_ast_commands current_level_commands_definitions auth_levels_names id;
        auth_level_is_cslprocess_internal = false;
      }
    else
      raise (LevelNotFound ("build_csl_ast_auth_levels -> The authentication level \"" ^ current_level_name ^ "\" does not exist."));
  ) parsed_csl_levels_definitions

let build_arg_separator chars can_be_multiple = {
  arg_separator_chars = chars;
  arg_separator_can_be_multiple = can_be_multiple;
}

let parsed_syscall_definition_to_syscall_definition parsed_syscall = 
  let parsed_syscall_args = parsed_syscall.Parser_types.parser_syscall_definition_args in

  let args = List.map (fun arg ->
    let numbers_regex = Str.regexp "^[0-9]+$" in

    if (Str.string_match numbers_regex arg 0 == false) && (arg <> ".*") then
      "\\\"" ^ arg ^ "\\\""
    else
      arg
  ) parsed_syscall_args in

  {
    syscall_definition_name = parsed_syscall.Parser_types.parser_syscall_definition_name;
    syscall_definition_args = args;
  }

let build_syscalls parsed_syscalls target_args =
  let syscalls_definition_accepted = List.map parsed_syscall_definition_to_syscall_definition parsed_syscalls.Parser_types.parser_syscalls_definition_accepted in
  let syscalls_definition_refused = List.map parsed_syscall_definition_to_syscall_definition parsed_syscalls.Parser_types.parser_syscalls_definition_refused in
  let syscalls_definition_ignored = List.map parsed_syscall_definition_to_syscall_definition parsed_syscalls.Parser_types.parser_syscalls_definition_ignored in

  let raw_syscalls_definition_authorized_syscalls = List.map (fun authorized_syscalls ->
    {
      authorized_syscalls_command_name = authorized_syscalls.Parser_types.parser_authorized_syscalls_command;
      authorized_syscalls_syscalls_names = authorized_syscalls.Parser_types.parser_authorized_syscalls_syscalls_names;
    }
  ) parsed_syscalls.Parser_types.parser_syscalls_definition_authorized_syscalls in

  let exists_other_commands_syscalls = List.exists (fun current_authorized_syscalls ->
    String.equal "other_commands" current_authorized_syscalls.authorized_syscalls_command_name
  ) raw_syscalls_definition_authorized_syscalls in

  let syscalls_definition_authorized_syscalls = match exists_other_commands_syscalls with
    | true -> raw_syscalls_definition_authorized_syscalls
    | false ->
        let other_commands_authorized_syscalls = {
          authorized_syscalls_command_name = "other_commands";
          authorized_syscalls_syscalls_names = [];
        } in

        other_commands_authorized_syscalls :: raw_syscalls_definition_authorized_syscalls
  in

  {
    syscalls_definition_command_to_run_args = target_args;
    syscalls_definition_accepted = syscalls_definition_accepted;
    syscalls_definition_refused = syscalls_definition_refused;
    syscalls_definition_ignored = syscalls_definition_ignored;
    syscalls_definition_authorized_syscalls = syscalls_definition_authorized_syscalls;
  }

let build_custom_seeds_definitions csl_ast_case_sensitivity parsed_custom_seeds =
  let associated_commands = match csl_ast_case_sensitivity with
    | false -> List.map String.lowercase_ascii parsed_custom_seeds.Parser_types.parser_custom_seeds_definition_associated_commands
    | true -> parsed_custom_seeds.Parser_types.parser_custom_seeds_definition_associated_commands
  in

  {
    custom_seeds_definition_associated_commands = associated_commands;
    custom_seeds_definition_seeds = parsed_custom_seeds.Parser_types.parser_custom_seeds_definition_seeds;
  }

let get_auth_levels_ids_and_names csl_ast =
  List.map (fun auth_level ->
    (auth_level.auth_level_id, auth_level.auth_level_name)
  ) csl_ast.csl_ast_auth_levels

let command_takes_args command =
  not (List.is_empty command.command_args)

let get_commands_and_if_they_take_args csl_ast =
  let commands_and_args_presence =
    List.fold_left (fun auth_levels_commands auth_level ->
      List.fold_left (fun commands current_auth_level_command ->
        commands @ [(current_auth_level_command.command_name, (command_takes_args current_auth_level_command))]
      ) auth_levels_commands auth_level.auth_level_commands
    ) [] csl_ast.csl_ast_auth_levels
  in

  List.sort_uniq (fun (command_1_name, command_1_arg_presence) (command_2_name, command_2_arg_presence) ->
    let increment = if command_1_arg_presence != command_2_arg_presence then
      List.length commands_and_args_presence
    else
      0
    in

    (String.compare command_1_name command_2_name) - increment
  ) commands_and_args_presence

let compare_two_transitions (a_source_auth_level_id, a_target_auth_level_id) (b_source_auth_level_id, b_target_auth_level_id) second_transition_coefficient =
  (a_source_auth_level_id - b_source_auth_level_id) + (second_transition_coefficient * (a_target_auth_level_id - b_target_auth_level_id))

let get_all_args_of_a_command csl_ast command_name =
  let csl_ast_auth_levels = csl_ast.csl_ast_auth_levels in

  let args = List.fold_left (fun args auth_level ->
    let interesing_command_in_current_auth_level_list = List.filter (fun command ->
      command.command_name == command_name
    ) auth_level.auth_level_commands in

    let interesing_command_in_current_auth_level_opt = List.nth_opt interesing_command_in_current_auth_level_list 0 in

    match interesing_command_in_current_auth_level_opt with
      | None -> args
      | Some command ->
          let command_args = List.filter_map (fun arg ->
            match arg.arg_value with
              | Anything -> None
              | Value v -> Some v
          ) command.command_args in

          args @ command_args
  ) [] csl_ast_auth_levels in

  List.sort_uniq String.compare args

let get_src_dst_auth_levels_ids_to_tuple_cmd_args csl_ast =
  let auth_levels = csl_ast.csl_ast_auth_levels in

  let srcs_dsts_2_cmds_args = List.fold_left (fun res current_auth_level ->
    let current_auth_level_id = current_auth_level.auth_level_id in
    let current_auth_level_commands = current_auth_level.auth_level_commands in

    res @ List.fold_left (fun res current_command ->
      let current_command_args = current_command.command_args in

      if List.is_empty current_command_args == true then
        ((current_auth_level_id, current_auth_level_id), (current_command, None)) :: res
      else
        res @ List.fold_left (fun res current_arg ->
          let current_arg_target_auth_level_id = current_arg.arg_auth_level_target_id in

          ((current_auth_level_id, current_arg_target_auth_level_id), (current_command, Some current_arg)) :: res
        ) [] current_command_args
    ) [] current_auth_level_commands
  ) [] auth_levels in

  let result = Hashtbl.create 1 in

  List.iter (fun (src_dst, cmd_arg) ->
    match Hashtbl.find_opt result src_dst with
      | None -> Hashtbl.replace result src_dst [cmd_arg]
      | Some v -> Hashtbl.replace result src_dst (cmd_arg :: v)
  ) srcs_dsts_2_cmds_args;

  result

let get_minimal_src_dst_auth_levels_ids_to_tuple_cmd_args csl_ast =
  let src_dst_auth_levels_ids_to_tuple_cmd_args = get_src_dst_auth_levels_ids_to_tuple_cmd_args csl_ast in
  let src_dst_auth_levels_ids_to_tuple_cmd_args_length = Hashtbl.length src_dst_auth_levels_ids_to_tuple_cmd_args in

  let minimal_map = Hashtbl.create src_dst_auth_levels_ids_to_tuple_cmd_args_length in

  Hashtbl.iter (fun src_dst cmds_args ->
    let important_cmds_args = List.filter (fun (_, arg) ->
      match arg with
        | None -> false
        | Some arg_v -> arg_v.arg_is_important == true
    ) cmds_args in

    let new_cmd_arg_list = match List.is_empty important_cmds_args with
      | false -> important_cmds_args
      | true -> [List.hd cmds_args]
    in

    Hashtbl.add minimal_map src_dst new_cmd_arg_list;
  ) src_dst_auth_levels_ids_to_tuple_cmd_args;

  minimal_map

let transform_minimal_src_dst_auth_levels_ids_to_tuple_cmd_args_to_src_auth_level_id_with_commands csl_ast =
  let minimal_src_dst_auth_levels_ids_to_tuple_cmd_args = get_minimal_src_dst_auth_levels_ids_to_tuple_cmd_args csl_ast in

  let res_list = Hashtbl.fold (fun (src, _) cmds_args res ->
    res @ List.fold_left (fun res (cmd, arg) ->
      let arg_v = match arg with
        | None -> []
        | Some v -> [v]
      in

      let new_cmd = { cmd with command_args = arg_v } in

      (src, new_cmd) :: res
    ) res cmds_args
  ) minimal_src_dst_auth_levels_ids_to_tuple_cmd_args [] in

  let result = Hashtbl.create 1 in

  List.iter (fun (src, cmd) ->
    match Hashtbl.find_opt result src with
      | None -> Hashtbl.replace result src [cmd]
      | Some v -> Hashtbl.replace result src (cmd :: v)
  ) res_list;

  result

let get_stared_commands_and_commands_with_args_from_and_to_auth_level_ids csl_ast =
  let first_arg_separator = List.nth csl_ast.csl_ast_arg_separator.arg_separator_chars 0 in
  let str_arg_separator = Char.escaped first_arg_separator in

  let all_commands = if csl_ast.csl_ast_adversarial_sequences_generation_mode == Full then
    begin
      let res = Hashtbl.create 1 in

      List.iter (fun auth_level ->
        Hashtbl.add res auth_level.auth_level_id auth_level.auth_level_commands;
      ) csl_ast.csl_ast_auth_levels;

      res
    end
  else
    transform_minimal_src_dst_auth_levels_ids_to_tuple_cmd_args_to_src_auth_level_id_with_commands csl_ast
  in

  let all_commands_length = Hashtbl.length all_commands in

  let result = Hashtbl.create 1 in

  Hashtbl.iter (fun auth_level_id transitions_commands ->
    List.iter (fun transitions_command ->
      let transitions_command_takes_args = command_takes_args transitions_command in
      let transitions_command_name = transitions_command.command_name in
      let transition_command_all_args = get_all_args_of_a_command csl_ast transitions_command.command_name in
      let transition_command_all_args_string =
        match csl_ast.csl_ast_split_adversarial_sequences_args with
          | true ->
            let transition_command_all_args_splited = List.map (fun command ->
              str_split_on_multiple_char command csl_ast.csl_ast_arg_separator.arg_separator_chars
            ) transition_command_all_args in

            let transposed_transition_command_all_args_splited = transpose_list_list transition_command_all_args_splited in

            let joined_sub_arguments = List.map (fun arg ->
              str_join "," arg
            ) transposed_transition_command_all_args_splited in

            str_join "} *-{" joined_sub_arguments
          | false -> str_join "," transition_command_all_args
      in

      if transitions_command_takes_args == true then
        List.iter (fun current_arg ->
          let command_with_arg = match current_arg.arg_value with
            | Anything -> (
                match transitions_command.command_appendix with
                  | None -> transitions_command_name ^ str_arg_separator ^ "*-{" ^ transition_command_all_args_string ^ "}"
                  | Some appendix -> transitions_command_name ^ str_arg_separator ^ "*-{" ^ transition_command_all_args_string ^ "}" ^ str_arg_separator ^ appendix
              )
            | Value arg_value -> (
                match transitions_command.command_appendix with
                  | None -> transitions_command_name ^ str_arg_separator ^ arg_value
                  | Some appendix -> transitions_command_name ^ str_arg_separator ^ arg_value ^ str_arg_separator ^ appendix
              )
          in

          let command_transition = (auth_level_id, current_arg.arg_auth_level_target_id) in

          match Hashtbl.find_opt result (command_with_arg, transitions_command) with
            | None ->
              Hashtbl.add result (command_with_arg, transitions_command) [command_transition];
            | Some value ->
              let raw_new_transitions = value @ [command_transition] in

              let new_transitions = List.sort_uniq (fun trs_a trs_b ->
                compare_two_transitions trs_a trs_b all_commands_length
              ) raw_new_transitions in

              Hashtbl.replace result (command_with_arg, transitions_command) new_transitions;
        ) transitions_command.command_args
      else (* A command without args does not have appendix (See parser.mly) *)
        let command_transition = (auth_level_id, auth_level_id) in

        match Hashtbl.find_opt result (transitions_command_name, transitions_command) with
        | None ->
          Hashtbl.add result (transitions_command_name, transitions_command) [command_transition];
        | Some value ->
          let raw_new_transitions = value @ [command_transition] in

          let new_transitions = List.sort_uniq (fun trs_a trs_b ->
            compare_two_transitions trs_a trs_b all_commands_length
          ) raw_new_transitions in

          Hashtbl.replace result (transitions_command_name, transitions_command) new_transitions
    ) transitions_commands
  ) all_commands;

  result

let get_max_auth_level_id csl_ast =
  let auth_levels = get_auth_levels_ids_and_names csl_ast in
  let result = ref 0 in

  List.iter (fun (id, _) ->
    if id > !result then
      result := id;
  ) auth_levels;

  !result

let get_commands_and_target_auth_levels_ids_for_an_auth_level_id csl_ast auth_level_id are_adversarial =
  let commands = get_stared_commands_and_commands_with_args_from_and_to_auth_level_ids csl_ast in

  Hashtbl.fold (fun (command_as_string, command_ast_node) adversarial_transitions acc ->
    (* On supprime les transitions qui partent de auth_level_id, et arrivent à auth_level_id (Réflexivité). *)
    let is_not_adversarial = List.exists (fun (source, destination) ->
      ((source == auth_level_id) && (source != destination)) || ((source == auth_level_id) && (destination == auth_level_id))
    ) adversarial_transitions in

    if (are_adversarial == true) && (is_not_adversarial == true) then
      acc
    else
      let target_auth_levels_ids = List.map (fun (source, destination) ->
        destination
      ) adversarial_transitions in

      let sorted_target_auth_levels_ids = List.sort_uniq (fun destination_a destination_b ->
        Int.compare destination_a destination_b
      ) target_auth_levels_ids in

      acc @ [(command_as_string, command_ast_node, sorted_target_auth_levels_ids)]
  ) commands []

let build_csl_ast_parameters parsed_csl_parameters =
  let parameters = {
    csl_ast_parameters_is_case_sensitive = false;
    csl_ast_parameters_arg_separator = build_arg_separator [' '] false;
    csl_ast_parameters_initial_auth_level_name = "";
    csl_ast_parameters_consider_other_commands = true;
    csl_ast_parameters_adversarial_sequences_generation = Full;
    csl_ast_parameters_ignore_empty_commands = false;
    csl_ast_parameters_ignored_chars = [];
    csl_ast_parameters_commands_prefix = None;
    csl_ast_parameters_adversarial_sequences_ending = None;
    csl_ast_parameters_split_adversarial_sequence_args = false;
    csl_ast_parameters_syscalls_getting_mode = Per_Commands;
  } in

  let parser_adversarial_sequences_generation_to_adversarial_sequences_generation = function
    | Parser_types.Full -> Full
    | Parser_types.Minimal -> Minimal
  in

  let parser_sycall_getting_mode_to_syscalls_getting_mode = function
    | Parser_types.Per_Commands -> Per_Commands
    | Parser_types.One_Shot -> One_Shot
  in

  List.iter (fun parameter ->
    match parameter with
    | Parser_types.Case_Sensitivity case_sensitivity -> parameters.csl_ast_parameters_is_case_sensitive <- case_sensitivity
    | Parser_types.Arg_Separator arg_separator -> parameters.csl_ast_parameters_arg_separator <- build_arg_separator arg_separator.parser_arg_separator_definition_chars arg_separator.parser_arg_separator_definition_can_be_multiple
    | Parser_types.Initial_Level initial_level_name -> parameters.csl_ast_parameters_initial_auth_level_name <- initial_level_name
    | Parser_types.Consider_Other_Commands consider_other_commands -> parameters.csl_ast_parameters_consider_other_commands <- consider_other_commands
    | Parser_types.Adversarial_Sequences_Generation adversarial_sequences_generation -> parameters.csl_ast_parameters_adversarial_sequences_generation <- parser_adversarial_sequences_generation_to_adversarial_sequences_generation adversarial_sequences_generation
    | Parser_types.Ignore_Empty_Commands ignore_empty_commands -> parameters.csl_ast_parameters_ignore_empty_commands <- ignore_empty_commands
    | Parser_types.Ignored_Chars ignored_chars -> parameters.csl_ast_parameters_ignored_chars <- ignored_chars
    | Parser_types.Commands_Prefix commands_prefix -> parameters.csl_ast_parameters_commands_prefix <- Some commands_prefix
    | Parser_types.Adversarial_Sequences_Ending advarsarial_sequences_ending -> parameters.csl_ast_parameters_adversarial_sequences_ending <- Some advarsarial_sequences_ending
    | Parser_types.Split_Adversarial_Sequences_Args split_adverarial_sequences_args -> parameters.csl_ast_parameters_split_adversarial_sequence_args <- split_adverarial_sequences_args
    | Parser_types.Syscalls_Getting_Mode syscalls_getting_mode -> parameters.csl_ast_parameters_syscalls_getting_mode <- parser_sycall_getting_mode_to_syscalls_getting_mode syscalls_getting_mode
  ) parsed_csl_parameters;

  parameters

let build_csl_ast_from_parsed_csl parsed_csl target_args =
  let parsed_csl_parameters = build_csl_ast_parameters parsed_csl.Parser_types.parser_csl_parameters in
  let parsed_auth_levels = parsed_csl.Parser_types.parser_csl_levels_definitions in
  let auth_levels_names = get_auth_levels_from_parsed_auth_levels parsed_auth_levels in
  let parsed_csl_initial_level = parsed_csl_parameters.csl_ast_parameters_initial_auth_level_name in

  let csl_initial_level_id = match parsed_csl_initial_level with
    | "" -> 0
    | _ -> get_level_id auth_levels_names parsed_csl_initial_level
  in

  let csl_ast_arg_separator = parsed_csl_parameters.csl_ast_parameters_arg_separator in

  if csl_initial_level_id == -1 then
    raise (LevelNotFound ("build_csl_ast_from_parsed_csl -> Le niveau de privilège \"" ^ parsed_csl_initial_level ^ "\" n'existe pas."));

  let csl_ast_syscalls = match parsed_csl.Parser_types.parser_csl_syscalls_option with
    | None -> None
    | Some syscalls -> Some (build_syscalls syscalls target_args)
  in

  let csl_ast_custom_seeds_definitions = match parsed_csl.Parser_types.parser_csl_custom_seeds_list_option with
    | None -> None
    | Some seeds -> Some (List.map (build_custom_seeds_definitions parsed_csl_parameters.csl_ast_parameters_is_case_sensitive) seeds)
  in

  let csl_ast_auth_levels = build_csl_ast_auth_levels parsed_auth_levels auth_levels_names in

  let void_auth_level = {
    auth_level_id = -2;
    auth_level_name = "__VOID_AUTH_LEVEL__";
    auth_level_commands = [];
    auth_level_is_cslprocess_internal = true;
  } in

  let csl_ast_auth_levels = if parsed_csl_parameters.csl_ast_parameters_consider_other_commands == true then
    let other_commands = List.fold_left (fun commands current_auth_level ->
      List.fold_left (fun commands current_command ->
        current_command.command_name :: commands
      ) commands current_auth_level.auth_level_commands
    ) [] csl_ast_auth_levels in

    let other_unique_commands = List.sort_uniq String.compare other_commands in
    let other_unique_commands_str = str_join "," other_unique_commands in

    let other_command_command = {
      command_name = "*-{" ^ other_unique_commands_str ^ "}";
      command_args = [];
      command_is_cslprocess_internal = true;
      command_appendix = None;
    } in

    let other_command_auth_level = {
      auth_level_id = -1;
      auth_level_name = "__OTHER_COMMAND__";
      auth_level_commands = [other_command_command];
      auth_level_is_cslprocess_internal = true;
    } in

    void_auth_level :: other_command_auth_level :: csl_ast_auth_levels
  else
    void_auth_level :: csl_ast_auth_levels
  in

  {
    csl_ast_is_case_sensitive = parsed_csl_parameters.csl_ast_parameters_is_case_sensitive;
    csl_ast_arg_separator = csl_ast_arg_separator;
    csl_ast_initial_auth_level_id = csl_initial_level_id;
    csl_ast_adversarial_sequences_generation_mode = parsed_csl_parameters.csl_ast_parameters_adversarial_sequences_generation;
    csl_ast_ignore_empty_commands = parsed_csl_parameters.csl_ast_parameters_ignore_empty_commands;
    csl_ast_auth_levels = csl_ast_auth_levels;
    csl_ast_syscalls = csl_ast_syscalls;
    csl_ast_ignored_chars = parsed_csl_parameters.csl_ast_parameters_ignored_chars;
    csl_ast_commands_prefix = parsed_csl_parameters.csl_ast_parameters_commands_prefix;
    csl_ast_adversarial_sequences_ending = parsed_csl_parameters.csl_ast_parameters_adversarial_sequences_ending;
    csl_ast_split_adversarial_sequences_args = parsed_csl_parameters.csl_ast_parameters_split_adversarial_sequence_args;
    csl_ast_syscalls_getting_mode = parsed_csl_parameters.csl_ast_parameters_syscalls_getting_mode;
    csl_ast_custom_seeds_definitions = csl_ast_custom_seeds_definitions;
  }

let print_csl_ast_syscalls syscalls =
  List.iter (fun syscall ->
    Printf.eprintf "- Nom : %s\n" syscall.syscall_definition_name;

    List.iter (fun arg ->
      Printf.eprintf "-- %s\n" arg;
    ) syscall.syscall_definition_args;
  ) syscalls

let print_csl_ast csl_ast =
  Printf.eprintf "Sensibilité à la casse : %s\n" (if csl_ast.csl_ast_is_case_sensitive == true then "Oui" else "Non");

  let _ = match csl_ast.csl_ast_split_adversarial_sequences_args with
    | true -> Printf.eprintf "Split des paramètres des séquences adverses activé\n"
    | false -> Printf.eprintf "Split des paramètres des séquences adverses désactivé\n"
  in

  let _ = if Option.is_some csl_ast.csl_ast_adversarial_sequences_ending then
    Printf.eprintf "Fin des séquences adverses : \"%s\"\n" (Option.get csl_ast.csl_ast_adversarial_sequences_ending);
  in

  let _ = match csl_ast.csl_ast_syscalls_getting_mode with
    | Per_Commands -> Printf.eprintf "Mode de récupération des appels systèmes : Commande par commande\n"
    | One_Shot -> Printf.eprintf "Mode de récupération des appels systèmes : Tout d'un coup\n"
  in

  Printf.eprintf "Caractères séparateur de champs :\n";

  let _ = List.iter (fun c ->
    Printf.eprintf "- '%c'\n" c
  ) csl_ast.csl_ast_arg_separator.arg_separator_chars in

  Printf.eprintf "Niveau d'authentification de départ : %d\n" csl_ast.csl_ast_initial_auth_level_id;
  Printf.eprintf "Affichage des niveaux d'authentification\n";

  List.iter (fun auth_level ->
    Printf.eprintf "- Niveau d'ID '%d' et de nom \"%s\" :\n" auth_level.auth_level_id auth_level.auth_level_name;

    List.iter (fun command ->
      Printf.eprintf "-- Commande courante : \"%s\"\n" command.command_name;

      List.iter (fun arg ->
        match arg.arg_value with
        | Anything -> Printf.eprintf "--- Argument générique\n";
        | Value value -> Printf.eprintf "--- Argument courant : \"%s\"\n" value;
        ;

        Printf.eprintf "---- Niveau d'authentification cible : %d\n" arg.arg_auth_level_target_id;
      ) command.command_args;

      match command.command_appendix with
        | Some a -> Printf.eprintf "-- Appendix : \"%s\"\n" a
        | None -> Printf.eprintf "-- Pas d'appendix\n"
    ) auth_level.auth_level_commands;
  ) csl_ast.csl_ast_auth_levels;

  let _ = match csl_ast.csl_ast_syscalls with
  | None -> Printf.eprintf "Pas de gestion des appels systèmes\n"
  | Some syscalls ->
      Printf.eprintf "Gestion des appels systèmes :\n";

      Printf.eprintf "Arguments de la commande pour lancer le programme testé : \"%s\"\n" syscalls.syscalls_definition_command_to_run_args;

      Printf.eprintf "Acceptés :\n";
      print_csl_ast_syscalls syscalls.syscalls_definition_accepted;

      Printf.eprintf "Refusés :\n";
      print_csl_ast_syscalls syscalls.syscalls_definition_refused;

      Printf.eprintf "Ignorés :\n";
      print_csl_ast_syscalls syscalls.syscalls_definition_ignored;

      Printf.eprintf "Autorisés :\n";
      List.iter (fun authorized_syscalls_definition ->
        Printf.eprintf "==> Commande %s\n" authorized_syscalls_definition.authorized_syscalls_command_name;

        List.iter (fun syscall ->
          Printf.eprintf "====> %s\n" syscall
        ) authorized_syscalls_definition.authorized_syscalls_syscalls_names
      ) syscalls.syscalls_definition_authorized_syscalls
  in

  match csl_ast.csl_ast_custom_seeds_definitions with
    | None -> Printf.eprintf "Pas de seeds customs\n"
    | Some seeds ->
        let _ = Printf.eprintf "Seeds customs :\n" in

        List.iter (fun seed_definition ->
          let commands = str_join "," seed_definition.custom_seeds_definition_associated_commands in

          let _ = Printf.eprintf "Commandes : %s\n" commands in

          List.iter (fun seed ->
            Printf.eprintf "- \"%s\"\n" seed
          ) seed_definition.custom_seeds_definition_seeds
        ) seeds

let get_syscalls csl_ast =
  match csl_ast.csl_ast_syscalls with
    | None -> []
    | Some syscalls ->
        let accepted_syscalls = List.fold_left (fun syscalls accepted_syscall ->
          accepted_syscall.syscall_definition_name :: syscalls
        ) [] syscalls.syscalls_definition_accepted in
        
        let refused_syscalls = List.fold_left (fun syscalls refused_syscall ->
          refused_syscall.syscall_definition_name :: syscalls
        ) [] syscalls.syscalls_definition_refused in

        List.sort_uniq String.compare (accepted_syscalls @ refused_syscalls)

let get_syscalls_command_to_run_args csl_ast =
  match csl_ast.csl_ast_syscalls with
  | None -> None
  | Some syscalls -> Some (syscalls.syscalls_definition_command_to_run_args)

let syscall_definition_to_string_syscall syscalls_defintions_list =
  List.map (fun syscall_defintion ->
    let syscall_name = syscall_defintion.syscall_definition_name in
    let syscall_args_str = str_join ", " syscall_defintion.syscall_definition_args in

    syscall_name ^ "(" ^ syscall_args_str ^ ")"
  ) syscalls_defintions_list

let get_syscalls_refused_as_str csl_ast =
  match csl_ast.csl_ast_syscalls with
  | None -> raise NoDeclaredSyscalls
  | Some syscalls -> syscall_definition_to_string_syscall syscalls.syscalls_definition_refused

let get_syscalls_ignored_as_str csl_ast =
  match csl_ast.csl_ast_syscalls with
  | None -> raise NoDeclaredSyscalls
  | Some syscalls -> syscall_definition_to_string_syscall syscalls.syscalls_definition_ignored

let get_syscalls_accepted_as_str csl_ast =
  match csl_ast.csl_ast_syscalls with
  | None -> raise NoDeclaredSyscalls
  | Some syscalls -> syscall_definition_to_string_syscall syscalls.syscalls_definition_accepted

let get_initial_auth_level_name csl_ast =
  let initial_auth_level_id = csl_ast.csl_ast_initial_auth_level_id in
  let initial_auth_level = get_auth_level_by_id csl_ast initial_auth_level_id in

  initial_auth_level.auth_level_name

let get_auth_levels_transitions_to_stared_commands csl_ast =
  let starred_commands = get_stared_commands_and_commands_with_args_from_and_to_auth_level_ids csl_ast in

  let transitions_to_commands_base = Hashtbl.create 1 in

  Hashtbl.fold (fun (cmd, _) cmd_transitions res ->
    let transitions = List.fold_left (fun res transition ->
      if List.exists (fun set_transition -> pairs_compare transition set_transition) res == false then
        transition :: res
      else
        res
    ) [] cmd_transitions in

    List.iter (fun transition ->
      match Hashtbl.find_opt res transition with
      | None -> Hashtbl.add res transition [cmd]
      | Some old_commands ->
          let new_commands = cmd :: old_commands in

          Hashtbl.replace res transition new_commands
    ) transitions;

    res
  ) starred_commands transitions_to_commands_base

let get_authorized_syscalls_as_hashtabl_definition_string csl_ast =
  match csl_ast.csl_ast_syscalls with
  | None -> raise NoDeclaredSyscalls
  | Some syscalls_definition ->
    let authorized_syscalls = syscalls_definition.syscalls_definition_authorized_syscalls in
    let number_of_commands = List.length authorized_syscalls in
    let commands_are_case_sensitive = csl_ast.csl_ast_is_case_sensitive in

    let hashtabl_filling_string = List.fold_left (fun acc current_authorized_syscalls ->
      let current_command = match commands_are_case_sensitive with
        | true -> current_authorized_syscalls.authorized_syscalls_command_name
        | false -> String.lowercase_ascii current_authorized_syscalls.authorized_syscalls_command_name 
      in

      let current_syscalls = current_authorized_syscalls.authorized_syscalls_syscalls_names in
      let current_syscalls_as_string = "[\"" ^ str_join "\"; \"" current_syscalls ^ "\"]" in

      acc ^ "let _ = Hashtbl.add authorized_syscalls \"" ^ current_command ^ "\" " ^ current_syscalls_as_string ^ "\n"
    ) "" authorized_syscalls in

    "let authorized_syscalls = Hashtbl.create " ^ string_of_int number_of_commands ^ "\n" ^ hashtabl_filling_string