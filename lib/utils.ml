let rec str_join sep = function
  | [] -> ""
  | str :: [] -> str
  | str :: remaining -> str ^ sep ^ (str_join sep remaining)

let rec range = function
  | 0 -> 0 :: []
  | max -> max :: range (max - 1)

let pairs_compare (a1, b1) (a2, b2) =
  a1 == a2 && b1 == b2

let equals a b =
  a == b

let minus_list a b =
  List.fold_left (fun res current_element ->
    if List.exists (equals current_element) b == false then
      current_element :: res
    else
      res
  ) [] a

let rec range_min ~min max =
  if max > min then
    max :: range_min ~min (max - 1)
  else
    min :: []

let str_transform str ~char_src ~char_dst =
  String.map (fun current_char ->
    if current_char == char_src then
      char_dst
    else
      current_char
  ) str

let rec transpose_list_list = function
  | [] -> []
  | [] :: next -> transpose_list_list next
  | (element :: next_list) :: next_list_list -> (element :: List.map List.hd next_list_list) :: transpose_list_list (next_list :: List.map List.tl next_list_list)

let str_split_on_multiple_char str chars =
  List.fold_left (fun result current_char ->
    List.fold_left (fun result current_str ->
      result @ String.split_on_char current_char current_str
    ) [] result
  ) [str] chars

module IntListHash = struct
  type t = int list

  let rec equal a b =
    match a, b with
      | [], [] -> true
      | _, [] | [], _ -> false
      | hd_a :: tl_a, hd_b :: tl_b ->
          if Int.equal hd_a hd_b then
            equal tl_a tl_b
          else
            false

  let hash l =
    let rec aux n current_hash = function
      | [] -> current_hash
      | hd :: tl ->
          let current_node_hash = current_hash + (n * hd) in

          current_node_hash + aux (n + 1) current_node_hash tl
    in

    aux 0 0 l
end