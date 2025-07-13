from RestrictedPython import compile_restricted
code = """
{{code}}
"""

byte_code = compile_restricted(code, '<inline>', 'eval')

print(eval(byte_code, {'__builtins__': {}}, {'__builtins__': {}}))

