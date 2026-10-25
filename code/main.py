import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, 'output.csv')
    engine.run(sample=False, out_path=out)
    print(f'wrote {out}')

if __name__ == '__main__':
    main()
