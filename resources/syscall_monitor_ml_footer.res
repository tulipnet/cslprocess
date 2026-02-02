type commands_behavior =
  | Normal
  | Strange

type problematic_command =
  | Undefined
  | Command of string

module StringSet = Set.Make(String)

let file2string_list file_name =
  if not(Sys.file_exists file_name) then
    raise (FileNotFoundException file_name);

  let file_channel = In_channel.open_bin file_name in
  let file_content = In_channel.input_all file_channel in
  let file_string_list = String.split_on_char '\n' file_content in

  In_channel.close file_channel;

  file_string_list

let char2string c =
  String.make 1 c

let parse_syscalls_file syscalls_file_path issued_commands =
  let syscalls_file_content = file2string_list syscalls_file_path in

  (* We want to remove the first and the last line of the syscall file.
   * They should be like :
   * - [ Process PID=46486 runs in 32 bit mode. ]
   * - +++ exited with 1 +++ *)
  let syscalls_file_content_without_header_and_footer = List.filteri (fun i file_line ->
    (i != 0) && (i < List.length syscalls_file_content)
  ) syscalls_file_content in

  (* We keep only syscalls that are in the "syscall_names" array *)
  let syscalls_file_content_with_only_interesting_syscalls = List.filter (fun syscall ->
    let is_ignored = List.exists (fun ignored_syscall_csl ->
      Str.string_match ignored_syscall_csl syscall 0
    ) ignored_syscalls in

    let is_an_accepted_command_related_syscall = List.exists (fun accepted_command_related_syscall_csl ->
      Str.string_match accepted_command_related_syscall_csl syscall 0
    ) accepted_syscalls in

    let is_a_refused_command_related_syscall = List.exists (fun refused_command_related_syscall_csl ->
      Str.string_match refused_command_related_syscall_csl syscall 0
    ) refused_syscalls in

    not is_ignored && (is_an_accepted_command_related_syscall || is_a_refused_command_related_syscall)
  ) syscalls_file_content_without_header_and_footer in

  let commands = match ignore_empty_commands with
    | false -> issued_commands
    | true ->
      let empty_command_regex = Str.regexp "^ *$" in
      let empty_command_regex_tabs = Str.regexp "^\r*$" in

      List.filter (fun command ->
        not (Str.string_match empty_command_regex command 0) &&
          not (Str.string_match empty_command_regex_tabs command 0)
      ) issued_commands
  in

  let number_of_commands = List.length commands in

  let filtered_syscalls_to_fit_the_number_of_commands = List.filteri (fun i syscall ->
    i < number_of_commands
  ) syscalls_file_content_with_only_interesting_syscalls in

  let number_of_syscalls = List.length filtered_syscalls_to_fit_the_number_of_commands in

  (* We ignore last commands that have no associated syscalls *)
  let filtered_commands = if number_of_commands > number_of_syscalls then
    List.filteri (fun i command ->
      i < number_of_syscalls
    ) commands
  else
    commands
  in

  let commands_to_syscalls = List.map2 (fun command syscall ->
    (command, syscall)
  ) filtered_commands filtered_syscalls_to_fit_the_number_of_commands in

  (* We remove refused commands to return only accepted commands *)
  let commands_to_syscalls_without_refused_commands =
    let normal_commands_to_syscalls_without_refused_commands = List.filter (fun (_, syscall) ->
      let is_not_refused = not (List.exists (fun refused_syscall_csl ->
        Str.string_match refused_syscall_csl syscall 0
      ) refused_syscalls) in

      let is_accepted = List.exists (fun accepted_syscall_csl ->
        Str.string_match accepted_syscall_csl syscall 0
      ) accepted_syscalls in

      is_not_refused && is_accepted
    ) commands_to_syscalls in

    List.map (fun (command, syscall) ->
      (command, Some syscall)
    ) normal_commands_to_syscalls_without_refused_commands
  in

  List.map (fun (command, _) ->
    command
  ) commands_to_syscalls_without_refused_commands

(* WARNING : We assume that commands are read by a syscall like `read(0, "<My command>", ...)` *)
let does_not_use_only_authorized_syscalls_with_problematic_syscalls commands_list full_syscalls_file_path =
  let full_syscalls_file_content = file2string_list full_syscalls_file_path in

  let filtered_full_syscalls_file_content = List.filter (fun file_line ->
    let syscall_regex = Str.regexp "[a-z0-9]+(.*" in

    Str.string_match syscall_regex file_line 0
  ) full_syscalls_file_content in

  let problematic_syscalls = Hashtbl.create 0 in (* command -> problematic syscalls set *)
  let current_command_id = ref (-1) in
  let commands_list_length = List.length commands_list in

  let (is_suspicious, _, _, problematic_command) = List.fold_left (fun (is_suspicious, current_command, current_arg, problematic_command) current_syscall ->
    let splited_current_syscall = String.split_on_char '(' current_syscall in
    let current_syscall_name = List.nth splited_current_syscall 0 in

    if String.equal current_syscall_name "read" then
      let splited_current_syscall_arguments = String.split_on_char ',' (List.nth splited_current_syscall 1) in
      let read_fd = int_of_string (List.nth splited_current_syscall_arguments 0) in

      if (read_fd == 0) && ((List.length commands_list > !current_command_id + 1) && (String.equal "\r" (List.nth commands_list (!current_command_id + 1)) == false)) then
        let _ = current_command_id := !current_command_id + 1 in

        if (!current_command_id < commands_list_length) then
          let full_command = List.nth commands_list !current_command_id in
          let splited_full_command = String.split_on_char arg_separator full_command in

          let command = match commands_are_case_sensitive with
            | true -> List.nth splited_full_command 0
            | false -> String.lowercase_ascii (List.nth splited_full_command 0)
          in

          let arg = if List.length splited_full_command >= 2 then
            List.nth splited_full_command 1
          else
            ""
          in

          if String.equal command "\n" == false then
            (is_suspicious, command, arg, problematic_command)
          else
            (is_suspicious, "", "", problematic_command)
        else
          (is_suspicious, current_command, current_arg, problematic_command)
      else
        (is_suspicious, current_command, current_arg, problematic_command)
    else if String.equal current_command "" == false then
      if is_suspicious == true then
        (is_suspicious, current_command, current_arg, problematic_command)
      else
        let authorized_syscalls_for_this_command_option = Hashtbl.find_opt authorized_syscalls current_command in

        match authorized_syscalls_for_this_command_option with
          | Some authorized_syscalls_for_this_command ->
              let new_is_suspicious = not (List.exists (fun syscall ->
                  String.equal current_syscall_name syscall
              ) authorized_syscalls_for_this_command) in

              let _ = if new_is_suspicious == true then
                match Hashtbl.find_opt problematic_syscalls current_command with
                  | None ->
                    let set = StringSet.singleton current_syscall_name in

                    Hashtbl.add problematic_syscalls current_command set
                  | Some problematic_syscalls_set_for_this_command ->
                    let new_set = StringSet.add current_syscall_name problematic_syscalls_set_for_this_command in

                    Hashtbl.replace problematic_syscalls current_command new_set
              in

              let new_problematic_command = match is_suspicious, new_is_suspicious with
                | true, _ | false, false -> problematic_command
                | false, true -> Command (current_command ^ char2string arg_separator ^ current_arg)
              in

              (new_is_suspicious, current_command, current_arg, new_problematic_command)
          | None ->
              let authorized_syscalls_for_other_commands = Hashtbl.find authorized_syscalls "other_commands" in

              let new_is_suspicious = not (List.exists (fun syscall ->
                String.equal current_syscall_name syscall
              ) authorized_syscalls_for_other_commands) in

              let _ = if new_is_suspicious == true then
                let result_other_commands_key = "other_commands (" ^ current_command ^ ")" in

                match Hashtbl.find_opt problematic_syscalls result_other_commands_key with
                  | None ->
                    let set = StringSet.singleton current_syscall_name in

                    Hashtbl.add problematic_syscalls result_other_commands_key set
                  | Some problematic_syscalls_set_for_this_command ->
                    let new_set = StringSet.add current_syscall_name problematic_syscalls_set_for_this_command in

                    Hashtbl.replace problematic_syscalls result_other_commands_key new_set
              in

              let new_problematic_command = match is_suspicious, new_is_suspicious with
                | true, _ | false, false -> problematic_command
                | false, true -> Command (current_command ^ char2string arg_separator ^ current_arg)
              in

              (new_is_suspicious, "", "", new_problematic_command)
    else
      (is_suspicious, "", "", problematic_command)
  ) (false, "", "", Undefined) filtered_full_syscalls_file_content in

  (is_suspicious, problematic_syscalls, problematic_command)

let string_set_hashtbl_merge a b =
  let _ = Hashtbl.iter (fun k v ->
    let k_in_a_opt = Hashtbl.find_opt a k in

    match k_in_a_opt with
      | None -> Hashtbl.add a k v
      | Some b_v ->
          let new_set = StringSet.union v b_v in

          Hashtbl.replace a k new_set
  ) b in

  a

let remove_prefix command ~prefix =
  match String.starts_with command ~prefix with
    | false -> command
    | true ->
        let command_length = String.length command in
        let prefix_length = String.length prefix in

        String.sub command prefix_length (command_length - prefix_length)

let () =
  if (Array.length Sys.argv) != 5 then
    Printf.printf "ERROR : argc != 5\n"
  else
    ();

  let commands_files_path = Sys.argv.(1) in
  let reduced_syscalls_files_path = Sys.argv.(2) in
  let full_syscalls_files_path = Sys.argv.(3) in
  let output_dir = Sys.argv.(4) in

  let commands_files_path_is_a_directory = Sys.is_directory commands_files_path in

  let files = Sys.readdir reduced_syscalls_files_path in
  let filesList = Array.to_list files in

  let filesListFiltered = List.filter (fun file ->
    file <> ".state" && file <> "full"
  ) filesList in

  let strange_commands_output_dir = output_dir ^ "/" ^ "strange" in

  Sys.mkdir strange_commands_output_dir 0o755;

  List.iteri (fun i file ->
    let commands_file = if commands_files_path_is_a_directory == true then
      commands_files_path ^ "/" ^ file
    else
      commands_files_path
    in

    let syscalls_file = reduced_syscalls_files_path ^ "/" ^ file in
    let full_syscalls_file = full_syscalls_files_path ^ "/" ^ file in

    let raw_commands = file2string_list commands_file in

    let commands = match commands_prefix with
      | None -> raw_commands
      | Some p -> List.map (fun command ->
          remove_prefix command ~prefix:p
        ) raw_commands
    in

    let (suspicious, problematic_syscalls, problematic_command) = does_not_use_only_authorized_syscalls_with_problematic_syscalls commands full_syscalls_file in
    let accepted_commands = parse_syscalls_file syscalls_file commands in

    let all_problematic_syscalls = Hashtbl.create 0 in

    let behavior = match suspicious with
      | false -> Normal
      | true ->
        let _ = string_set_hashtbl_merge all_problematic_syscalls problematic_syscalls in

        Strange
    in

    if (List.length accepted_commands > 0) || (behavior == Strange) then
      let accepted_commands_as_string = match behavior with
        | Normal ->
            List.fold_left (fun result command ->
              result ^ command ^ "\n"
            ) "" accepted_commands
        | Strange ->
            List.fold_left (fun result command ->
              result ^ command ^ "\n"
            ) "" commands
      in

      let output_file_name = match behavior with
        | Normal -> (output_dir ^ "/" ^ (Filename.basename commands_file) ^ "_" ^ (Int.to_string i))
        | Strange -> (strange_commands_output_dir ^ "/" ^ (Filename.basename commands_file) ^ "_" ^ (Int.to_string i))
      in

      if String.length accepted_commands_as_string > 0 then
        let output_file_fd = Unix.openfile output_file_name [Unix.O_RDWR ; Unix.O_CREAT] 0o644 in
        let output_file_write_result = Unix.write output_file_fd (Bytes.of_string accepted_commands_as_string) 0 (String.length accepted_commands_as_string) in

        if output_file_write_result == 0 then
          Printf.printf "Unable to write in %s" output_file_name;

        Unix.close output_file_fd;

      if Hashtbl.length all_problematic_syscalls > 0 then
        let problematic_syscalls_description_str = Hashtbl.fold (fun command problematic_syscalls str ->
          let problematic_syscalls_as_list = StringSet.elements problematic_syscalls in

          str ^
            "- " ^
            command ^
            "\n" ^
            List.fold_left (fun str2 problematic_syscall ->
              str2 ^ "-- " ^ problematic_syscall ^ "\n"
            ) "" problematic_syscalls_as_list
        ) all_problematic_syscalls "" in

        let _ = Printf.printf "Problematic syscalls :\n%s\n" problematic_syscalls_description_str in

        let report_file_path = strange_commands_output_dir ^ "/__report__.txt" in

        let report_file_fd = match Sys.file_exists report_file_path with
          | true -> Unix.openfile report_file_path [Unix.O_RDWR ; Unix.O_APPEND] 0o644
          | false -> Unix.openfile report_file_path [Unix.O_RDWR ; Unix.O_CREAT] 0o644
        in

        let _ = Unix.write report_file_fd (Bytes.of_string problematic_syscalls_description_str) 0 (String.length problematic_syscalls_description_str) in
        Unix.close report_file_fd
  ) filesListFiltered