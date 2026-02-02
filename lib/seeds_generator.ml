open Ast
open Adversarial_generator

let replace_wildcard_by_concrete_value csl_ast csl_ast_command concrete_value =
  let first_arg_separator = List.nth csl_ast.csl_ast_arg_separator.arg_separator_chars 0 in

  match (csl_ast_command.command_is_cslprocess_internal, csl_ast_command.command_appendix) with
    | true, _ -> concrete_value ^ "\n"
    | false, None -> csl_ast_command.command_name ^ Char.escaped first_arg_separator ^ concrete_value ^ "\n" (* Not command_ast_node_name, because unescaped if applicable *)
    | false, Some command_appendix -> csl_ast_command.command_name ^ Char.escaped first_arg_separator ^ concrete_value ^ Char.escaped first_arg_separator ^ command_appendix ^ "\n" (* Not command_ast_node_name, because unescaped if applicable *)

let internal_generate_seeds_for_all_commands csl_ast custom_seeds_definitions =
  let all_commands = generate_all_commands csl_ast in
  let is_case_sensitive = csl_ast.csl_ast_is_case_sensitive in

  List.map (fun (id, command, command_ast_node) ->
    if String.contains command '*' then
      let command_ast_node_name = match is_case_sensitive with
        | false -> String.lowercase_ascii command_ast_node.command_name
        | true -> command_ast_node.command_name
      in

      let custom_seeds_for_this_current_command_opt = List.find_opt (fun current_custom_seed_definition ->
        List.exists (fun command_name ->
          String.equal command_name command_ast_node_name
        ) current_custom_seed_definition.custom_seeds_definition_associated_commands
      ) custom_seeds_definitions in

      match custom_seeds_for_this_current_command_opt with
        | None ->
            let default_seed_for_this_command = replace_wildcard_by_concrete_value csl_ast command_ast_node "aaaa" in

            (id, Some [default_seed_for_this_command], true)
        | Some custom_seeds_for_this_current_command ->
            let all_applied_seeds_for_this_command = List.map (fun current_seed ->
              replace_wildcard_by_concrete_value csl_ast command_ast_node current_seed
            ) custom_seeds_for_this_current_command.custom_seeds_definition_seeds in

            (id, Some all_applied_seeds_for_this_command, true)
    else
      (id, None, false)
  ) all_commands

let generate_seeds_for_all_commands csl_ast =
  match csl_ast.csl_ast_custom_seeds_definitions with
    | None -> internal_generate_seeds_for_all_commands csl_ast []
    | Some custom_seeds_definitions -> internal_generate_seeds_for_all_commands csl_ast custom_seeds_definitions

let concatenate_seeds list =
  let rev_list = List.rev list in

  let rec aux = function
    | [] -> []
    | [l] -> l
    | l1 :: l2 :: rest ->
        List.flatten (
          List.map (fun s1 ->
            List.map (fun s2 ->
              s1 ^ s2
            ) l2
          ) l1
        ) @ aux rest
  in

  aux rev_list

let generate_seeds_for_adversarial_sequences_with_precedence_relation csl_ast adversarial_sequences_with_precedence_relation =
  let all_commands = generate_all_commands csl_ast in
  let seeds_for_all_commands = generate_seeds_for_all_commands csl_ast in

  List.fold_left (fun result (current_adversarial_sequence_commands_ids, _) ->
    let seeds_for_all_commands = List.fold_left (fun current_seeds_for_this_precendence current_command_id ->
      if current_command_id != -1 then
        let custom_seeds_for_this_command_option = List.find_opt (fun (id, _, _) ->
          id == current_command_id
        ) seeds_for_all_commands in

        let (_, command, current_command_ast_node) = List.find (fun (command_id, _, _) ->
          command_id == current_command_id
        ) all_commands in

        let seeds_for_this_command = match custom_seeds_for_this_command_option with
          | None -> [command]
          | Some (_, seeds_options, wildcarded) -> (
              match wildcarded, seeds_options with
                | false, _ -> [command]
                | true, None -> [replace_wildcard_by_concrete_value csl_ast current_command_ast_node "aaaa"]
                | ture, Some seeds -> seeds
          )
        in

        List.fold_left (fun seeds_for_this_adversarial_sequence current_seed_for_this_command ->
          current_seed_for_this_command :: seeds_for_this_adversarial_sequence
        ) [] seeds_for_this_command :: current_seeds_for_this_precendence
      else
        current_seeds_for_this_precendence
    ) [] current_adversarial_sequence_commands_ids in

    (current_adversarial_sequence_commands_ids, concatenate_seeds seeds_for_all_commands) :: result
  ) [] adversarial_sequences_with_precedence_relation