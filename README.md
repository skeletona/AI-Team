# AI army
<p align="center">Let AI solve CTF for you!</p>

<p align="center">
  <img src="./.github/website-preview.png" alt="website preview"/>
</p>

<b>DISCLAIMER</b>: If you want to learn something, <b>DO NOT</b> use AI army. It makes you lazy, stupid and may be considered as cheating.

## Requirements
- `Codex` installed with tokens (ChatGPT Plus)
- `Docker compose`
- `python 3.13`

## Quickstart

1) Installation
```shell
git clone https://github.com/skeletona/AI-army && cd AI-army
```

2) Dependencies
```shell
pip install -r requirements.txt
```

3) Settings
```shell
vim .env
```

4) Run
```shell
./main run
```

After the tasks are downloaded, go to http://localhost:8000

## Usage
Available commands:
| Command   | Purpose                  | Example usage
| --------- | ------------------------ | ----------------------------------------- |
| `start`   | Run AI army              | `./main run codex website --attach codex` |
| `stop`    | Run Codex for every task | `./main stop web`                         |
| `restart` | Restart service          | `./main restart website -a`               |
| `status`  | Show status              | `./main status`                           |
| `attach`  | Attach to service        | `./main attach codex`                     |
| `clean`   | Cleaning                 | `./main clean all`                        |
| `sql`     | Look in database         | `./main sql`                              |

### Completions
You can add AI army commands to shell completions
```shell
./main --install-completion
export PATH="$PATH:."
exec $SHELL
```
<b>Careful</b>: Works only if current directory is in your PATH

## Configuring

Look in `.env` if you want to change something

## How it works

| File                | Purpose                  | Usage               |
| ------------------- | ------------------------ | ------------------- |
| `.env`              | Settings                 | `vim .env`          |
| `main.py`           | User commands            | `./main -h`         |
| `ctfd.py`           | Download tasks from CTFd | `./main download`   |
| `codex.py`          | Run Codex for every task | `./main codex -a`   |
| `website.py`        | Flask server             | `./main website -a` |
| `db.py`             | Interact with sqlite3    | `./main sql`        |
| `models.py`         | Auxiliary garbage        |                     |
| `logs/running.json` | Info about processes     |                   |

## Philosophy

I believe that if something can be automated, it should be. That's the basic of human evolution.
CTF won't die, it will transform to address cybersecurity challenges.
Smart guys won't lose their jobs, they are always needed.

<details>
<summary>But how do I learn?</summary>

Yeah, I don't know. Learn something AI cannot do. Just be better.
</details>

## Results

Also I want to see what level can AI achieve by itself, and its dynamics over time, so here I will collect statistics on CTF placements of AI army.

Conditions:
- No human intervention: just hit start and let it go
- When the 5 hour token limits are reached, wait for them to be restored
- Place counts in open worldwide division

| CTF | Place | Tasks solved |
| --- | ----- | ------------ |
|     |       |              |

Full statistics can be found in [Statistics](/statistics/)

## Features
- All AIs are in docker
- Manually managing tasks
- Modifiable prompts
- AI logs on website

#### TODOs (maybe)
- Rewrite all in Rust 🦀(in process)
- Web-configurator for .env
- Codex logs summarization
- Full-fledged chat window
- Other AIs support (Gemini CLI)
- Non-CTFd boards
- AI-manager of AIs
- Extended statistics
- Attack-Defense support
- Auto run on ctftime events
- Collect statistics
