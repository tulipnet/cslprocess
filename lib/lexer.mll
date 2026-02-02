{
    open Lexing
    open Parser
    open Exceptions
    open Parser_types

    let next_line lexbuf =
        let pos = lexbuf.lex_curr_p in
        lexbuf.lex_curr_p <-
        { pos with pos_bol = lexbuf.lex_curr_pos;
            pos_lnum = pos.pos_lnum + 1
        }

    let string_buffer = Buffer.create 256
    let current_char = ref 'a'
    let backslashed_char = ref false

    let char_for_backslash = function
        | 'n' -> '\010'
        | 'r' -> '\013'
        | 'b' -> '\008'
        | 't' -> '\009'
        | c -> c

    let keywords = Hashtbl.create 1

    (* Mot-clés du langage *)
    let _ = Hashtbl.add keywords "case_sensitivity" CASE_SENSITIVITY
    let _ = Hashtbl.add keywords "yes" YES
    let _ = Hashtbl.add keywords "no" NO
    let _ = Hashtbl.add keywords "arg_separator" ARG_SEPARATOR
    let _ = Hashtbl.add keywords "level" LEVEL
    let _ = Hashtbl.add keywords "arg" ARG
    let _ = Hashtbl.add keywords "initial_level" INITIAL_LEVEL
    let _ = Hashtbl.add keywords "multiple" MULTIPLE
    let _ = Hashtbl.add keywords "levels" LEVELS
    let _ = Hashtbl.add keywords "syscall_monitor" SYSCALL_MONITOR
    let _ = Hashtbl.add keywords "accepted" ACCEPTED
    let _ = Hashtbl.add keywords "refused" REFUSED
    let _ = Hashtbl.add keywords "other_commands" OTHER_COMMANDS
    let _ = Hashtbl.add keywords "ignored" IGNORED
    let _ = Hashtbl.add keywords "adversarial_sequences_generation_mode" ADVERSARIAL_SEQUENCES_GENERATION_MODE
    let _ = Hashtbl.add keywords "full" FULL
    let _ = Hashtbl.add keywords "minimal" MINIMAL
    let _ = Hashtbl.add keywords "important" IMPORTANT
    let _ = Hashtbl.add keywords "authorized_syscalls" AUTHORIZED_SYSCALLS
    let _ = Hashtbl.add keywords "ignore_empty_commands" IGNORE_EMPTY_COMMANDS
    let _ = Hashtbl.add keywords "ignored_chars" IGNORED_CHARS
    let _ = Hashtbl.add keywords "commands_prefix" COMMANDS_PREFIX
    let _ = Hashtbl.add keywords "adversarial_sequences_ending" ADVERSARIAL_SEQUENCES_ENDING
    let _ = Hashtbl.add keywords "split_adversarial_sequences_args" SPLIT_ADVERSARIAL_SEQUENCES_ARGS
    let _ = Hashtbl.add keywords "syscalls_getting_mode" SYSCALLS_GETTING_MODE
    let _ = Hashtbl.add keywords "per_commands" PER_COMMANDS
    let _ = Hashtbl.add keywords "one_shot" ONE_SHOT
    let _ = Hashtbl.add keywords "seeds" SEEDS
}

let word = ['a'-'z' 'A'-'Z' '0'-'9' '_''-']++
let white = [' ' '\t']
let newline = '\r' | '\n' | "\r\n"
let comment = "//"[^'\r''\n']+('\r' | '\n' | "\r\n" | eof)
let int = ['0'-'9']*
let character = ['a'-'z' 'A'-'Z' '0'-'9' '='';''|'':''_''-''.''"']

rule read =
    parse
    | white { read lexbuf }
    | newline { Parser_types.current_line := !Parser_types.current_line + 1; next_line lexbuf; read lexbuf }
    | eof { EOF }
    | comment { Parser_types.current_line := !Parser_types.current_line + 1; next_line lexbuf; read lexbuf }
    | '=' { EQUALS }
    | ';' { SEMICOLON }
    | '|' { PIPE }
    | ':' { COLON }
    | ',' { COMMA}
    | '"' {
        let _ = backslashed_char := false in

        Buffer.clear string_buffer;
        string lexbuf;
        ID (Buffer.contents string_buffer)
    }
    | '>' { GREATER }
    | '(' { LEFT_PARENTHESIS }
    | ')' { RIGHT_PARENTHESIS }
    | '_' { UNDERSCORE }
    | ''' {
        let _ = backslashed_char := false in

        char lexbuf;
        CHAR (!current_char)
    }
    | int as i { INT (int_of_string i) }
    | word as w {
        let lowercase_w = String.lowercase_ascii w in

        try
            Hashtbl.find keywords lowercase_w
        with
            Not_found -> ID w
      }
    | _ {
        raise (SyntaxError ("ERROR in line " ^ string_of_int !current_line ^ " : Characters \"" ^ Lexing.lexeme lexbuf ^ "\" are invalid."))
      }
and string =
    parse
    | '"' { () }
    | '\\' {
        let _ = if !backslashed_char == false then
            backslashed_char := true
        else
            let _ = Buffer.add_char string_buffer '\\' in

            backslashed_char := false
        in

        string lexbuf
    }
    | _ as c {
        let _ = if !backslashed_char == true then
            let _ = backslashed_char := false in

            current_char := char_for_backslash c
        else
            current_char := c
        in

        Buffer.add_char string_buffer !current_char;
        string lexbuf
    }
    | eof { raise (SyntaxError ("ERROR : Not ended sting in line " ^ string_of_int !current_line ^ " ; Invalid characters : \"" ^ Lexing.lexeme lexbuf ^ "\".")) }
and char =
    parse
    | ''' { () }
    | '\\' {
        let _ = backslashed_char := true in

        char lexbuf
    }
    | _ as c {
        let _ = if !backslashed_char == true then
            current_char := char_for_backslash c
        else
            current_char := c
        in

        char lexbuf
    }
    | eof { raise (SyntaxError ("ERROR : character descriptor not closed in line " ^ string_of_int !current_line ^ ".")) }