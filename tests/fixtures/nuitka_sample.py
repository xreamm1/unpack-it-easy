"""UIE known-source Nuitka fixture."""
def score_position(material, mobility):
    return material * 10 + mobility * 3

def describe(value):
    return "winning" if value > 20 else "balanced"

if __name__ == "__main__":
    value = score_position(3, 4)
    print("UIE_NUITKA_FIXTURE", value, describe(value))
