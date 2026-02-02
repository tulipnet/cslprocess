(** Custom exceptions that can may be thrown by the CSLProcess lib. *)

(** Occurs when there is a syntax error in the CSL File. May be thrown by the {!module:Lexer} or the {!module:Parser}. *)
exception SyntaxError of string

(** Occurs when an {!type:Ast.auth_level} is not found. Typically thrown when trying to request the {!module:Ast} to get an unknown object. *)
exception LevelNotFound of string

(** Occurs when trying to use syscalls-related functions of the {!module:Ast} while there is no a [syscall_monitor] part in the CSL specification. *)
exception NoDeclaredSyscalls