(** Module embedding some helpers functions *)

(** [str_join "," ["foo"; "bar"] -> "foo,bar"] joins all elements of the [string list] into a single string by using the provided separator. {b It does not output a separator after the last string of the [string list].} *)
val str_join : string -> string list -> string

(** [range 5 -> [5; 4; ...; 0]] : Make a list from the max bound to 0 in the descending order. *)
val range : int -> int list

(** [pair_compare a b] compares if the value of the tuple [a] equals the value of the tuple [b] *)
val pairs_compare : ('a * 'b) -> ('a * 'b) -> bool

(** [equals a b = a == b]. Useful in functions passed in functions like [List.exists]. *)
val equals : 'a -> 'a -> bool

(** [minus_list [0;1;3;5] [0;4] -> [5; 3; 1]] : Returns a new list that contains elements that only exists in the first list, and not in the second. *)
val minus_list : 'a list -> 'a list -> 'a list

(** [range_min min=3 5 -> [5; 4; 3]] : Same as {!val:range}, but with a lower bound different to 0. *)
val range_min : min:int -> int -> int list

(** Replace all the occurrences of [char_src] by [char_dst] in the [string]. *)
val str_transform : string -> char_src:char -> char_dst:char -> string

(** [transpose_list_list [[1; 2;]; [3; 4]] -> [[1; 3]; [2; 4]]] : Transpose an ['a list list] like a matrix transposition. *)
val transpose_list_list : 'a list list -> 'a list list

(** [str_split_on_multiple_char "foo bar,biz" [' '; ','] -> ["foo"; "bar"; "biz"]] : Split a [string] into a [string list] on some separators. *)
val str_split_on_multiple_char : string -> char list -> string list

module IntListHash : sig
    type t = int list

    val equal : int list -> int list -> bool
    val hash : int list -> int
end