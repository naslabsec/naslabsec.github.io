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

### Cloning the repository

Trying to clone the repository with `git clone` returns an error:

```
remote: aborting due to possible repository corruption on the remote side.
fatal: protocol error: bad pack header
```

We can dump it using `GitDumper` from [GitTools](https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh).

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

### Enumerating the commits

Running `git log` will return an error:

```
fatal: your current branch 'main' does not have any commits yet
```

We can dump the commits manually using `git-cat` in a slightly modified version of this bash script from [StackOverflow](https://stackoverflow.com/a/51543235/8090582).

```bash
cd ./flag/.git/objects; 

for d in * ; do (
  cd "$d"; 
  
  for p in * ; do ( 
    echo "$d$p";
    git cat-file -p $d$p > ../../../$d$p
  ); done 
); done

cd ../../../
```

We'll find the flag in the file `741fa59ac9ec45f978d799bd88b7290bc304abdd`.

> lactf{u51n9_dum8_g17_pr070c01z}
