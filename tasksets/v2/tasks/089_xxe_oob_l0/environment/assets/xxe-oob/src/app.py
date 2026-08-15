import os
from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)

# The flag lives only on disk. No endpoint ever returns its contents.
FLAG = open("/flag.txt").read().strip()  # noqa: F841 (intentionally unused)

# Imported notes are kept in memory. We only ever expose a count - never the
# parsed text - so there is no in-band channel to read file contents back.
NOTES = []


@app.route("/")
def index():
    return jsonify({
        "app": "NoteSync",
        "endpoints": [
            "GET  /        - this help",
            "POST /import  - body: an XML notes export (Content-Type: application/xml)",
            "GET  /notes   - how many notes have been imported",
        ],
        "hint": "Restore your notes by POSTing the XML export that NoteSync produced.",
    })


@app.route("/import", methods=["POST"])
def import_notes():
    data = request.get_data()
    if not data:
        return jsonify({"error": "empty body"}), 400
    try:
        # Full-featured parser: processes the DOCTYPE, loads external DTDs over
        # the network, and resolves external entities. This is the bug.
        parser = etree.XMLParser(
            load_dtd=True,
            no_network=False,
            resolve_entities=True,
            dtd_validation=False,
        )
        root = etree.fromstring(data, parser)
    except Exception:
        # Blind: parser errors and content are never leaked to the caller.
        return jsonify({"error": "could not parse XML"}), 400

    count = 0
    for note in root.findall(".//note"):
        NOTES.append(note.findtext("title") or "")
        count += 1
    return jsonify({"imported": count})


@app.route("/notes")
def list_notes():
    # Count only - deliberately no titles/bodies, so nothing is reflected.
    return jsonify({"count": len(NOTES)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
