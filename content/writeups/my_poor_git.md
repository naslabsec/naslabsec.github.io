---
title: 'LA CTF 2024'
challenge: 'My Poor Git'
date: 2024-02-19T00:00:00+01:00
author: 'Signum98'
description: 'Writeup for the LA CTF 2024 challenge "My Poor Git"' 
cover: '/img/la_ctf_2024/logo.png'
tags: ['misc']
draft: false
---

```
My poor git server! I think someone took a hammer to the server and ruined a few of the files!

The git repo is available at 
https://poor-git.chall.lac.tf/flag.git
```

### Quick look

Accessing the homepage or the git repository from the browser returns an error `404 Not Found`, this indicates that directory listing is not available.

{{< figure src="/img/la_ctf_2024/404.png" position="left" caption="Error 404 Not Found" captionPosition="left">}}

Accessing the `HEAD` file gives us its output, this indicates that the content of the `.git` folder is accessible over internet.

{{< figure src="/img/la_ctf_2024/HEAD.png" position="left" caption="HEAD file content" captionPosition="left">}}

### Cloning the repository

Trying to clone the repository with `git clone` returns an error:

```
remote: aborting due to possible repository corruption on the remote side.
fatal: protocol error: bad pack header
```

We can dump the content of the `.git` folder using [GitDumper](https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh) from `GitTools`.

But first we'll need to remove the url check at line 54:

```bash
if [[ ! "$BASEURL" =~ /$GITDIR/$ ]]; then
    echo -e "\033[31m[-] /$GITDIR/ missing in url\033[0m";
    exit 0;
fi
```

```bash
$ ./gitdumper.sh https://poor-git.chall.lac.tf/flag.git/ ./flag
```

{{< figure src="/img/la_ctf_2024/dump.png" position="left" caption="GitDumper output" captionPosition="left">}}

### Enumerating the commits

We can try to obtain informations about the repository by analyzing the commits.

Running `git log` returns an error:

```
fatal: your current branch 'main' does not have any commits yet
```

We can dump them using the [extractor](https://github.com/internetwache/GitTools/blob/master/Extractor/extractor.sh) script from `GitTools`.

```bash
./extractor.sh ./flag/ extract_folder
```

{{< figure src="/img/la_ctf_2024/extraction.png" position="left" caption="Extractor output" captionPosition="left">}}

We'll find the flag in the file `extract_folder/4-e3fde9187ea42af07d95bb3e891b6338738810ab/flag.txt`.

> lactf{u51n9_dum8_g17_pr070c01z}
