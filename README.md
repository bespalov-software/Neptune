
# Development

Tool dependencies:
- `swiftlint` (brew install swiftlint)
- `swiftformat` (brew install swiftformat)
- `pre-commit` (pip install pre-commit)

See:
- https://github.com/nicklockwood/SwiftFormat
    - https://github.com/nicklockwood/SwiftFormat/blob/main/Rules.md
- https://github.com/realm/SwiftLint
    - https://realm.github.io/SwiftLint/rule-directory.html
- https://pre-commit.com/#install

To run swiftformat:
```
swiftformat .
```

To run swiftlint:
```
swiftlint
```
Format commit messages according to: https://www.conventionalcommits.org/en/v1.0.0/

To install pre-commit hooks:

Create or activate the python virtual environment:
```
python3 -m venv .venv
source .venv/bin/activate
```

Install the pre-commit hook:
```
pip3 install pre-commit
```

To deactivate the python virtual environment:
```
deactivate
```
