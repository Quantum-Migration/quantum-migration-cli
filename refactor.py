#!/usr/bin/env python3
import ast
import astunparse

# Mapping from RSA functions to PQC helper functions.
RSA_TO_PQC_MAPPING = {
    "newkeys": "oqs_generate_keypair",
    "encrypt": "oqs_encrypt",
    "decrypt": "oqs_decrypt",
    "sign": "oqs_sign",
    "verify": "oqs_verify"
}

class RSA2PQCTransformer(ast.NodeTransformer):
    def visit_Call(self, node):
        # Replace calls like rsa.<func>(...) with their PQC equivalent.
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id.lower() == "rsa":
                func_name = node.func.attr
                if func_name in RSA_TO_PQC_MAPPING:
                    new_func_name = RSA_TO_PQC_MAPPING[func_name]
                    new_call = ast.Call(
                        func=ast.Name(id=new_func_name, ctx=ast.Load()),
                        args=node.args,
                        keywords=node.keywords
                    )
                    # Inline comment to mark migration.
                    comment = ast.Expr(value=ast.Constant(value=f"[Info]: Migrated rsa.{func_name}() to {new_func_name}()"))
                    return [new_call, comment]
        return self.generic_visit(node)

class RemoveRSAImportTransformer(ast.NodeTransformer):
    def visit_Import(self, node):
        # Remove "import rsa".
        new_names = [n for n in node.names if n.name != 'rsa']
        return node if new_names else None

    def visit_ImportFrom(self, node):
        # Remove any "from rsa import ..." statements.
        if node.module == 'rsa':
            return None
        return node

class AddPQCImportTransformer(ast.NodeTransformer):
    def __init__(self):
        self.found = False

    def visit_ImportFrom(self, node):
        if node.module == 'pqc_helpers':
            self.found = True
        return node

    def visit_Module(self, node):
        self.generic_visit(node)
        # If no import from pqc_helpers exists, add one at the top.
        if not self.found:
            import_node = ast.ImportFrom(
                module="pqc_helpers",
                names=[
                    ast.alias(name="oqs_generate_keypair", asname=None),
                    ast.alias(name="oqs_encrypt", asname=None),
                    ast.alias(name="oqs_decrypt", asname=None),
                    ast.alias(name="oqs_sign", asname=None),
                    ast.alias(name="oqs_verify", asname=None)
                ],
                level=0
            )
            node.body.insert(0, import_node)
        return node

def refactor_code_ast(code):
    """
    Parses and transforms the code, replacing RSA functions with PQC equivalents.
    """
    try:
        tree = ast.parse(code)
        tree = RemoveRSAImportTransformer().visit(tree)
        tree = RSA2PQCTransformer().visit(tree)
        tree = AddPQCImportTransformer().visit(tree)
        ast.fix_missing_locations(tree)
        return astunparse.unparse(tree)
    except Exception as e:
        return f"# [Error]: AST transformation failed due to {e}\n{code}"

def refactor_file(file_path, vulnerabilities, dry_run=False):
    """
    Reads a Python file, refactors it using AST-based transformation, and writes the changes.
    If dry_run is True, prints the changes without modifying the file.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        original_code = f.read()

    refactored_code = refactor_code_ast(original_code)

    if dry_run:
        print(f"\n--- [Dry Run] Refactored code for {file_path} ---\n")
        print(refactored_code)
        return original_code

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(refactored_code)

    return refactored_code
