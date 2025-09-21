# Regex Tester GUI (Tkinter, pure Python 3.10)

A desktop app for **building, testing, and managing regular expressions**.  
No external dependencies — just Python 3.10+ and the standard library (`tkinter`, `re`, `json`).

---

## Highlights

- **Tester tab**
  - Type/paste a regex and test against large text.
  - Toggle flags: `IGNORECASE`, `MULTILINE`, `DOTALL`, `VERBOSE`, `ASCII`.
  - Built‑in **Sample text** dropdown to quickly load long examples.
  - **Find** highlights all matches in the editor and lists them with byte offsets.
  - Double‑click a result to jump to and highlight that match in the text.
  - **Clear Results** resets the list and removes highlights.

- **Patterns tab**
  - A searchable table of named presets (**Name / RegExp**).
  - Filtering as you type over names or expressions.
  - Selecting a row loads the pattern into the Tester.

- **Builder tab (visual regex builder)**
  - Three‑pane workflow:
    - **Left** — token palette: literals, raw snippets, character classes, anchors, word boundaries,
      alternation `|`, grouping (capturing/non‑capturing/named), lookaheads/behinds, backreferences.
      Quantifier widget (`?`, `*`, `+`, `{n}`, `{min,}`, `{min,max}`) with **Lazy** option.
      Quick **Suggestions** for common recipes.
    - **Center** — sequence list of tokens with **Up/Down**, **Remove**, **Clear all**.
      Select a range to **Wrap** (group/lookaround) or **Apply quantifier** (auto wraps the selection).
    - **Right** — live preview (compiled pattern or error), flag toggles, token breakdown,
      actions: **Send to Tester**, **Save as preset**, **Copy regex**.
  - Sends the built pattern and flags straight to the Tester for matching.

- **Presets**
  - Ships with an extensive starter set (emails, URLs, IPs, dates/times, paths, UUIDs, hex colors, HTML/Markdown, etc.).
  - **Presets → Export presets…** writes all presets to JSON.
  - **Presets → Import presets…** merges JSON presets (updates by name, adds new entries).
  - Easy to scale to ~250 presets.

---

## Requirements

- **Python 3.10+**
- Windows/macOS/Linux with a GUI.
- No third‑party packages required.

> On Linux, make sure the `tk`/`tkinter` package for your Python is installed (often a separate package).

---

## Run

```bash
python regex_tester.py
```

- The app starts on the **Tester** tab.
- Switch to **Patterns** to browse presets, or **Builder** to construct a pattern visually.
- Use the menu **Presets** to export/import JSON collections of patterns.

---

## Usage tips

- **Tester**
  - Flags affect the whole pattern. If you need embedded flag scopes, use `(?i:...)`, etc.
  - Offsets shown in the results list are 0‑based character positions within the text buffer.

- **Builder**
  - **Literal** escapes your input safely (outside character classes).
  - **Class [chars]** and **Negated class [^chars]** escape the minimum needed (`\`, `^`, `-`, `]`).
  - **Apply quantifier** wraps your current selection into a non‑capturing group `(?: … )` then appends the chosen quantifier; toggle **Lazy** to add `?`.
  - **Wrap** supports capturing `(...)`, non‑capturing `(?:...)`, **named** `(?P<name>...)` (validated), and lookarounds `(?=...) (?!...) (?<=...) (?<!...)`.
  - Use **Send to Tester** to try the built pattern against real text immediately.

- **Patterns**
  - Click a row to load the regex into the Tester.
  - The filter searches both the name and the expression.

---

## Add or edit presets

You have two easy options:

1. **Edit the code**: open `regex_tester.py` and extend the `BUILTIN_PATTERNS` list near the top:
   ```python
   BUILTIN_PATTERNS = [
       ("Email (loose)", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
       # add more ...
   ]
   ```
2. **Use JSON import/export**:
   - Export to create a template JSON.
   - Edit JSON (`[{ "name": "...", "regex": "..." }, ...]`).
   - Import to update/add entries by name (existing names are replaced; new names are appended).

---

## Windows: create a desktop shortcut (optional)

This repo includes **`make_shortcut.cmd`**, which creates a desktop `.lnk` pointing to the app using a GUI‑friendly Python (`pythonw.exe`) when available.

**Steps**  
1. Put `make_shortcut.cmd` next to `regex_tester.py` (or `regex_tester.pyw`).  
2. Double‑click `make_shortcut.cmd`.  
3. It detects a `pythonw.exe` in a local `.venv`/`venv` if present, otherwise tries system `pythonw`.  
4. A shortcut named like **“RegExTesterGUI.lnk”** appears on your Desktop.

> Tip: Rename `APPNAME` inside the `.cmd` to change the shortcut name. 

---

## Packaging (optional)

If you want a single‑file executable for Windows, tools like **PyInstaller** can bundle Tkinter apps:
```bash
pyinstaller --noconsole --onefile --name RegexTesterGUI regex_tester.py
```
*(Packaging is optional; the app runs fine with plain Python.)*

---

## License

MIT (or your preferred license).


