pyinstaller --onefile create_address.py ^
--add-data=".\base\wallet\puzzles\p2_conditions.clvm.hex;base\wallet\puzzles" ^
--add-data=".\base\wallet\puzzles\calculate_synthetic_public_key.clvm.hex;base\wallet\puzzles" ^
--add-data=".\base\wallet\puzzles\p2_delegated_puzzle_or_hidden_puzzle.clvm.hex;base\wallet\puzzles"