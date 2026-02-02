# CSLProcess

- [CSLProcess](#cslprocess)
  - [1) Build and usage](#1-build-and-usage)
    - [1.1) Dependencies](#11-dependencies)
    - [1.2) Building](#12-building)
    - [1.3) Usage](#13-usage)
  - [2) CSL Language](#2-csl-language)
    - [2.1) `<parameters>`](#21-parameters)
    - [2.2) `<authentication_levels>`](#22-authentication_levels)
    - [2.3) `<syscall_monitor>`](#23-syscall_monitor)
      - [2.3.1) Detection of issued commands, and associated answers](#231-detection-of-issued-commands-and-associated-answers)
      - [2.3.2) Detection of hidden features based on usage of unauthorized system calls](#232-detection-of-hidden-features-based-on-usage-of-unauthorized-system-calls)

## 1) Build and usage

### 1.1) Dependencies

* Ocaml / Opam
* Dune
* Menhir

### 1.2) Building

```bash
$ make
```

When it is done, you should find a `cslprocess` symlink pointing to `_build/default/cslprocess.exe` (Warning : Not tested on Windows or Mac OS/X).

When running, it should output :
```bash
$ ./cslprocess
[cslprocess] Running cslprocess !
ERROR : The CSL file is missing as program argument, and the maximal depth of the generated adversarial sequences.
```

A developer-side documentation is available by building CSLProcess with this:
```bash
$ make doc
$ firefox doc.html
```

### 1.3) Usage

```bash
./cslprocess <csl_file_path : string> <adversarial_sequences_depth : int> <target_args : string> [output_directory : string optional]
```

## 2) CSL Language

Main body of a CSL specification (The whole language is described in following sections, and in [parser.mly](parser.mly)) :
```
<csl> ::= <parameters> <authentication_levels> <syscall_monitor>
```

A minimal example of CSL specification is provided in the [minimal](./minimal/) folder. In the [csl](./csl/) folder, there are CSL specifications of protocols studied in the paper.

The separator for `<'a list>` tokens is pipe (`|`).

### 2.1) `<parameters>`

If not specified, parameters are optional. The default value is provided in the formal grammar:
```
<parameters> ::= initial_authentication_level = <string>; <parameters> 
                   => (REQUIRED) Initial authentication in the authentication automaton
               | case_sensitivity = (yes | no); <parameters>
                   => Commands need to be case-sensitive (Yes by default / No);
               | arg_separator = <char list> (|multiple); <parameters>
                   => Possible separator characters between a command and its arguments (' ' by default).
                      In adversarial sequences, the first one is used.
                      "multiple" means an argument separator can be repeated multiple times between a command and its argument.
               | other_commands = (yes | no); <parameters>
                   => Generate wildcard that matches commands that are not described in the CSL specification
                      (Yes by default)
               | adversarial_sequences_generation_mode = (full | minimal); <parameters>
                   => Do we generate all possible adversarial sequences (Full), or only important adversarial sequences (Minimal) ? (Full by default)
               | ignore_empty_commands = (yes | no); <parameters>
                   => Ignore inputs that are empty (False by default)
               | ignored_chars = <char list>; <parameters>
                   => Ignore problematic chars in the generated oracle (Empty by default)
               | commands_prefix = <string>; <parameters>
                   => Prefix to add before generated adversarial sequences ("" by default)
               | adversarial_sequences_ending = <string>
                   => Ending of adversarial sequences ("" by default)
               | split_adversarial_sequences_args = (yes | no)
                   => Do we split complex arguments in adversarial sequences (Example : Command "LOGIN" with arg "homer marge" should be split in "homer" "marge", or "homer marge").
                      Split is done wrt the arg_separator parameter. By default, no.
               | syscalls_getting_mode = (per_commands | one_shot)
                   => When tracing the target to record system calls, do we send the input command by command, or the whole adversarial sequence in an unique shot ?
                      (By default, per_commands)
```

### 2.2) `<authentication_levels>`

An authentication level is defined by a name, and has one or more commands with, per command, one or more args.

Each command is written by the following construction:
```
<command> ::= <name> (<args list>)

<arg> ::= arg == <string> => level = <string>
            => Declared argument
        | _
            => Anything except already declared arguments
```

An example of a command is:
```
PASS (arg == "maggie" => level = authenticated | _)
```

For the command `PASS`, two usages are allowed : `PASS maggie` and `PASS homer`. If the argument is `maggie`, the current authentication level will be `authenticated`, but if the argument is `homer`, the current authentication level will stay the same.

More advanced usages can be found in the [csl](./csl/) directory.

A key point is if the parameter (See [2.1)](#21-parameters)) `syscalls_getting_mode` is set to minimal, it is possible to add an `important` flag at the end, to force the adversarial sequence generator to generate adversarial commands for this argument, wrt the automaton.

### 2.3) `<syscall_monitor>`

This part permits to strengthen the oracle by giving clues about how to :
1. Detect when a command is issued to the protocol implementation
2. Detect if a system call is forbidden (Revealing a potential backdoor)

#### 2.3.1) Detection of issued commands, and associated answers

The `<syscall_monitor>` part of the specification is divided in 3 sections :
- Accepted
- Refused
- Ignored

Each section contains system calls templates that are translated to regular expression by the oracle engine. Basically, they can be:
```
write(1, "1.*", ".*")
write(0, "UNKNOWN 4.*", ".*")
```

The associated formal grammar is:
```
<syscalls_set> ::= <syscall>;
                 | <syscalls_set>, <syscall>;

<syscall_args> ::= <string>
                 | <syscall_args>, <string>

<syscall> ::= <string>(<syscall_args)
```

#### 2.3.2) Detection of hidden features based on usage of unauthorized system calls

In this part of the CSL specification, the goal is to enumerate all system calls a command is allowed to use. A global case `other_commands` exists for all commands that have not explicit system calls.

For example, with the declaration `USER(read, write, pipe, open)`, the command `USER` is allowed to do `pipe()`, but is not allowed to do an `execve("/bin/bash")`.

The formal grammar of this part is:
```
<authorized_syscalls> ::= <authorized_syscalls_for_a_command>;
                        | <authorized_syscalls>, <authorized_syscalls_for_a_command>;

<syscalls_list> ::= <string>
                  | <syscalls_list>, <string>

<authorized_syscalls_for_a_command> ::= <string>(<syscalls_list>)
```