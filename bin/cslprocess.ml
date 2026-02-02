open Cslprocess_v2

module IntListHashtbl = Hashtbl.Make(Utils.IntListHash)

let main () =
  Printf.printf "[cslprocess] Running cslprocess !\n";

  if (Sys.file_exists "/usr/local/bin/buffered_pipe_writer" == false) then
    begin
      Printf.printf "[cslprocess] ERROR : The binary \"buffered_pipe_writer\" is not installed\n";
      Printf.printf "             - Please consider install it with the submodule, and \"make all && sudo make install\"\n";

      exit 1;
    end;

  if (Array.length Sys.argv == 4) || (Array.length Sys.argv == 5) then
    let csl_filename = Sys.argv.(1) in
    let adversarial_sequences_depth = int_of_string (Sys.argv.(2)) in
    let target_args = Sys.argv.(3) in
    let output_directory = if Array.length Sys.argv == 5 then
      Sys.argv.(4)
    else
      Filename.dirname csl_filename
    in

    if Sys.file_exists csl_filename == true then
      let lexbuf = Lexing.from_channel (open_in csl_filename) in
      let parsed_csl =
        try
          Parser.csl Lexer.read lexbuf
        with
          Exceptions.SyntaxError error -> Printf.printf "[cslprocess] ERROR: Unable to parse the provided CSL file (%s)\n" error;
          exit 1;
      in

      Printf.printf "[cslprocess] Generation of the CSL's associated AST.\n";

      let csl_ast = Ast.build_csl_ast_from_parsed_csl parsed_csl target_args in

      let _ = Ast.print_csl_ast csl_ast in

      Printf.printf "[cslprocess] Automaton generation.\n";

      let csl_ast_lexer = Automaton_generator.ocamllex_build_lexer csl_ast in
      let lexer_source_path = output_directory ^ "/lexer.mll" in

      if Sys.file_exists lexer_source_path == true then
        Sys.remove lexer_source_path;

      let lexer_source_out_channel = open_out lexer_source_path in
      
      Printf.fprintf lexer_source_out_channel "%s" csl_ast_lexer;
      close_out lexer_source_out_channel;

      let csl_ast_parser = Automaton_generator.menhir_build_parser csl_ast in
      let parser_source_path = output_directory ^ "/parser.mly" in

      if Sys.file_exists parser_source_path == true then
        Sys.remove parser_source_path;

      let parser_source_out_channel = open_out parser_source_path in

      Printf.fprintf parser_source_out_channel "%s" csl_ast_parser;
      close_out parser_source_out_channel;

      let automaton_source_path = output_directory ^ "/automaton.ml" in

      if Sys.file_exists automaton_source_path == true then
        Sys.remove automaton_source_path;

      let automaton_source_out_channel = open_out automaton_source_path in

      let automaton_ml = Automaton_generator.build_automaton_ml csl_ast in

      Printf.fprintf automaton_source_out_channel "%s" automaton_ml;
      close_out automaton_source_out_channel;

      Printf.printf "[cslprocess] Automaton compilation.\n";

      Sys.chdir output_directory;

      let _ = Sys.command (Filename.quote_command ("ocamllex") ["lexer.mll"]) in
      let _ = Sys.command (Filename.quote_command ("menhir") ["parser.mly"]) in
      let _ = Sys.command (Filename.quote_command ("ocamlc") ["-c"; "parser.mli"]) in
      let _ = Sys.command (Filename.quote_command ("ocamlc") ["-c"; "lexer.ml"]) in
      let _ = Sys.command (Filename.quote_command ("ocamlc") ["-c"; "parser.ml"]) in
      let _ = Sys.command (Filename.quote_command ("ocamlc") ["-c"; "automaton.ml"]) in
      let _ = Sys.command (Filename.quote_command ("ocamlc") ["-o"; "automaton"; "lexer.cmo"; "parser.cmo"; "automaton.cmo"]) in

      Printf.printf "[cslprocess] Generating adversarial sequences generation with a maximal depth of %d.\n" adversarial_sequences_depth;

      let adversarial_sequences_with_precedences = Adversarial_generator.generate_adversarial_sequences_and_get_precedence_relation csl_ast adversarial_sequences_depth in
      let adversarial_sequences_dir = "adversarial_sequences" in

      let _ = Sys.command (Filename.quote_command "rm" ["-rf"; adversarial_sequences_dir]) in

      Sys.mkdir adversarial_sequences_dir 0o744;

      let adversarial_sequence_depth = fun adversarial_sequence ->
        let split_adversarial_sequence = String.split_on_char '\n' adversarial_sequence in

        (* Adversarial sequences end by "\n", so this is the reason for the -1 *)
        (List.length split_adversarial_sequence) - 1
      in

      let adversarial_sequences_by_depth = Hashtbl.create 1 in

      List.iter (fun adversarial_sequence_with_precedences ->
        let (_, adversarial_sequence) = adversarial_sequence_with_precedences in
        let depth = adversarial_sequence_depth adversarial_sequence in

        match Hashtbl.find_opt adversarial_sequences_by_depth depth with
          | None -> Hashtbl.add adversarial_sequences_by_depth depth [adversarial_sequence_with_precedences];
          | Some adversarial_sequences -> Hashtbl.replace adversarial_sequences_by_depth depth (adversarial_sequence_with_precedences :: adversarial_sequences);
      ) adversarial_sequences_with_precedences;

      let range_adversarial_sequences_depth = Utils.range adversarial_sequences_depth in
      let current_adversarial_sequence_id = ref 0 in
      let adversarial_sequence_ids = IntListHashtbl.create 1 in

      let adversarial_sequence_ending = match csl_ast.csl_ast_adversarial_sequences_ending with
        | None -> "\n"
        | Some e -> e
      in

      List.iter (fun current_depth ->
        let adversarial_sequences_with_precedences_opt = Hashtbl.find_opt adversarial_sequences_by_depth current_depth in

        match adversarial_sequences_with_precedences_opt with
        | Some adversarial_sequences_with_precedences ->
          List.iter (fun (current_precedences, current_adversarial_sequence) ->
            let filtered_precedences = List.filter (fun current_precedence ->
              current_precedence > -1 (* -1 stands for the empty command *)
            ) current_precedences in

            let _ = IntListHashtbl.add adversarial_sequence_ids current_precedences !current_adversarial_sequence_id in

            let current_precedences_as_string = List.map Int.to_string filtered_precedences in
            let current_precedences_string = Utils.str_join "-" current_precedences_as_string in

            let current_adversarial_sequence_file_path = adversarial_sequences_dir ^ "/wid=" ^ Int.to_string !current_adversarial_sequence_id ^ ";depth=" ^ Int.to_string current_depth ^ ";content=" ^ current_precedences_string in

            let current_adversarial_sequence_file_out_channel = open_out current_adversarial_sequence_file_path in

            Printf.fprintf current_adversarial_sequence_file_out_channel "%s" (current_adversarial_sequence ^ adversarial_sequence_ending);

            close_out current_adversarial_sequence_file_out_channel;

            incr current_adversarial_sequence_id;
          ) adversarial_sequences_with_precedences;
        | None -> ()
      ) range_adversarial_sequences_depth;

      Printf.printf "[cslprocess] Generating all wildcarded commands\n";

      let all_commands = Adversarial_generator.generate_all_commands csl_ast in
      let all_commands_dir = "all_commands" in

      let _ = Sys.command (Filename.quote_command "rm" ["-rf"; all_commands_dir]) in

      Sys.mkdir all_commands_dir 0o744;

      List.iter (fun (i, command, _) ->
        let cmd_out_channel = open_out (all_commands_dir ^ "/cmd_id:" ^ Int.to_string i ^ ".cmd") in

        Printf.fprintf cmd_out_channel "%s" command;

        close_out cmd_out_channel;
      ) all_commands;

      match csl_ast.csl_ast_syscalls with
      | None -> ()
      | Some syscalls ->
        Printf.printf "[cslprocess] \"syscall_monitor\" tools generation\n";

        let syscall_monitor_dir = Filename.basename "syscall_monitor" in

        let _ = Sys.command (Filename.quote_command "rm" ["-rf"; syscall_monitor_dir]) in

        Sys.mkdir syscall_monitor_dir 0o744;
        Sys.chdir syscall_monitor_dir;

        let get_syscalls_sh_filename = "get_syscalls.sh" in
        let get_syscalls_sh_out_channel = open_out get_syscalls_sh_filename in
        let get_syscalls_sh_content = Syscall_monitor.generate_get_syscalls_sh csl_ast in

        Printf.fprintf get_syscalls_sh_out_channel "%s" get_syscalls_sh_content;
        
        let _ = Sys.command (Filename.quote_command "chmod" ["+x"; get_syscalls_sh_filename]) in

        let syscall_monitor_ml_filename = "syscall_monitor.ml" in
        let syscall_monitor_ml_out_channel = open_out syscall_monitor_ml_filename in
        let syscall_monitor_ml_content = Syscall_monitor.generate_syscall_monitor_ml csl_ast in

        Printf.fprintf syscall_monitor_ml_out_channel "%s" syscall_monitor_ml_content;

        close_out syscall_monitor_ml_out_channel;

        let _ = Sys.command (Filename.quote_command "ocamlc" ["-I"; "+str"; "-I"; "+unix"; "str.cma"; "unix.cma"; "syscall_monitor.ml"; "-o"; "syscall_monitor"]) in

        Sys.chdir "..";

        let _ = Printf.printf "[cslprocess] Generating seeds\n" in

        let custom_seeds_per_commands_dir = "seeds_per_commands" in

        let seeds = Seeds_generator.generate_seeds_for_all_commands csl_ast in

        let _ = Sys.mkdir custom_seeds_per_commands_dir 0o744 in

        let _ = List.iter (fun (current_custom_seeded_command_id, current_custom_seeded_command_seeds, _) ->
          let seeds_for_this_command = match current_custom_seeded_command_seeds with
            | None -> ["aaaa"]
            | Some seeds -> seeds
          in

          List.iteri (fun seed_number seed ->
            let current_seed_filename = "cmd_id:" ^ Int.to_string current_custom_seeded_command_id ^ "_" ^ Int.to_string seed_number ^ ".seed" in
            let current_seed_out_channel = open_out (custom_seeds_per_commands_dir ^ "/" ^ current_seed_filename) in

            let _ = Printf.fprintf current_seed_out_channel "%s" seed in

            close_out current_seed_out_channel
          ) seeds_for_this_command
        ) seeds in

        let seeds_dir = "seeds" in

        let _ = Sys.mkdir seeds_dir 0o744 in

        let seeds = Seeds_generator.generate_seeds_for_adversarial_sequences_with_precedence_relation csl_ast adversarial_sequences_with_precedences in

        List.iter (fun (prec, seed) ->
          let prec_without_minus_one = List.filter (fun prec ->
            prec != -1
          ) prec in

          let depth = List.length prec_without_minus_one in
          let current_precedences_string = Utils.str_join "-" (List.map Int.to_string prec_without_minus_one) in
          let id = IntListHashtbl.find adversarial_sequence_ids prec in

          List.iteri (fun seed_id seed ->
            let current_seed_out_path = seeds_dir ^ "/wid=" ^ Int.to_string id ^ ";depth=" ^ Int.to_string depth ^ ";content=" ^ current_precedences_string ^ ";seed_id=" ^ Int.to_string seed_id in
            let current_seed_out_channel = open_out current_seed_out_path in

            let _ = Printf.fprintf current_seed_out_channel "%s" (seed ^ adversarial_sequence_ending) in

            close_out current_seed_out_channel
          ) seed
        ) seeds
    else
      Printf.printf "ERROR : The file \"%s\" does not exist.\n" csl_filename
  else
    Printf.printf "ERROR : The CSL file is missing as program argument, and the maximal depth of the generated adversarial sequences.\n"

let () = main ()