import os
import json
import sys

# Determine base directory (folder containing the .exe or .py)
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

BASE_PATH = os.path.join(BASE_DIR, 'whitelisted_domains.json')
NEW_PATH = os.path.join(BASE_DIR, 'new_whitelisted_domains.json')

# Ensure whitelist file exists
if not os.path.exists(BASE_PATH):
    with open(BASE_PATH, 'w') as f:
        json.dump([], f)

# Load JSON into sets

def load_set(path):
    try:
        return set(json.load(open(path)))
    except Exception:
        return set()

base_set = load_set(BASE_PATH)
new_set = load_set(NEW_PATH)

# Helper: check if a domain is covered by any wildcard in a given whitelist

def covered_by_wildcard(domain, whitelist):
    d = domain.lower()
    for allowed in whitelist:
        if allowed.startswith('*.'):
            base = allowed[2:].lower()
            # wildcard covers subdomains, not the base itself
            if d.endswith('.' + base):
                return True
    return False

# Pre-clean base_set: if a wildcard exists, drop any covered entries
clean_base = set()
for entry in base_set:
    if not covered_by_wildcard(entry, base_set - {entry}):
        clean_base.add(entry)
base_set = clean_base

# Begin merge
merged = set(base_set)
seen = set(base_set)

print(f"Base entries: {len(base_set)}, New seen: {len(new_set)}")
for domain in sorted(new_set):
    if domain in seen or covered_by_wildcard(domain, merged):
        continue

    choice = input(f"Add domain '{domain}'? [y/N/wildcards]: ").strip().lower()
    # simple yes
    if choice == 'y':
        merged.add(domain)
        seen.add(domain)
        continue

    # wildcard-driven expansion
    if choice == 'w':
        parts = domain.split('.')
        # iterate from highest-level (excluding TLD-only)
        for i in range(len(parts) - 2, -1, -1):
            candidate = '.'.join(parts[i:])
            # ask about base domain
            yn_base = input(f"  Add base '{candidate}'? [y/N]: ").strip().lower()
            if yn_base == 'y':
                merged.add(candidate)
                seen.add(candidate)
            # ask about wildcard
            wc = f"*.{candidate}"
            yn_wc = input(f"  Add wildcard '{wc}'? [y/N]: ").strip().lower()
            if yn_wc == 'y':
                merged.add(wc)
                seen.add(wc)
                break
        continue

    # default: skip
    print(f"Skipping '{domain}'")

# Final cleanup: remove specific domains covered by wildcards
final_set = set()
for entry in merged:
    if not covered_by_wildcard(entry, merged - {entry}):
        final_set.add(entry)

# Write updated whitelist
with open(BASE_PATH, 'w') as f:
    json.dump(sorted(final_set), f, indent=2)

print(f"Merged {len(final_set)} entries → {BASE_PATH}")



# import os, json, sys

# # Determine base directory (folder containing the .exe or .py)
# if getattr(sys, 'frozen', False):
#     BASE_DIR = os.path.dirname(sys.executable)
# else:
#     BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# BASE = os.path.join(BASE_DIR, 'whitelisted_domains.json')
# NEW = os.path.join(BASE_DIR, 'new_whitelisted_domains.json')

# # Ensure whitelist file exists
# if not os.path.exists(BASE):
#     with open(BASE, 'w') as f:
#         json.dump([], f)

# # Load sets
# def load_set(path):
#     try:
#         return set(json.load(open(path)))
#     except Exception:
#         return set()

# base_set = load_set(BASE)
# new_set = load_set(NEW)

# # Helpers
# def covered_by_wildcard(domain, whitelist):
#     for allowed in whitelist:
#         if allowed.startswith('*.'):
#             base = allowed[2:].lower()
#             # Ensure *.abc.com doesn't cover abc.com
#             if domain.endswith(base) and domain != base:
#                 return True
#     return False

# def is_covered(entry, others):
#     for other in others:
#         if other == entry:
#             continue
#         if other.startswith('*.'):
#             base = other[2:]
#             # Ensure *.abc.com doesn't cover abc.com
#             if entry.endswith(base) and entry != base:
#                 return True
#     return False

# # Main merge logic
# merged = set(base_set)
# added_domains = set(base_set)

# print(f"Base entries: {len(base_set)}, New seen: {len(new_set)}")

# for d in sorted(new_set):
#     if d in added_domains or covered_by_wildcard(d, added_domains):
#         continue

#     # Ask for the base domain first
#     base_domain = d
#     choice_base = input(f"Add base domain '{base_domain}'? [y/N/w]: ")
#     if choice_base.lower() == 'y':
#         added_domains.add(base_domain)
#         merged.add(base_domain)
    
#     # Now handle the wildcard addition
#     elif choice_base.lower() == 'w':
#         parts = d.split('.')
#         for i in range(len(parts) - 2, -1, -1):
#             wc = '*.' + '.'.join(parts[i:])
#             yn_wildcard = input(f"  Add wildcard '{wc}'? [y/N]: ")
#             if yn_wildcard.lower() == 'y':
#                 merged.add(wc)
#                 added_domains.add(wc)

#                 # Now ask if user wants to add the base (non-wildcard) domain too
#                 if base_domain not in added_domains:
#                     yn_base = input(f"  Wildcard added. Also add base '{base_domain}'? [y/N]: ")
#                     if yn_base.lower() == 'y':
#                         merged.add(base_domain)
#                         added_domains.add(base_domain)
#                 break

# # Second pass: wildcard exists, but base doesn't → ask
# for entry in sorted(merged):
#     if entry.startswith('*.'):
#         base = entry[2:]
#         if base not in merged:
#             yn = input(f"Wildcard '{entry}' exists, but base '{base}' is not in list. Add it? [y/N]: ")
#             if yn.lower() == 'y':
#                 merged.add(base)

# # Remove redundant entries (handle the most inclusive domain removing more specific ones)
# filtered = set()
# for entry in merged:
#     others = merged - {entry}
#     if not is_covered(entry, others):
#         filtered.add(entry)

# # Write final list
# with open(BASE, 'w') as f:
#     json.dump(sorted(filtered), f, indent=2)

# print(f"Merged {len(filtered)} entries → {BASE}")





# import os, json, sys

# # Determine base directory (folder containing the .exe or .py)
# if getattr(sys, 'frozen', False):
#     BASE_DIR = os.path.dirname(sys.executable)
# else:
#     BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# BASE = os.path.join(BASE_DIR, 'whitelisted_domains.json')
# NEW = os.path.join(BASE_DIR, 'new_whitelisted_domains.json')

# # Ensure whitelist file exists
# if not os.path.exists(BASE):
#     with open(BASE, 'w') as f:
#         json.dump([], f)

# # Load sets
# def load_set(path):
#     try:
#         return set(json.load(open(path)))
#     except Exception:
#         return set()

# base_set = load_set(BASE)
# new_set = load_set(NEW)

# # Helpers
# def covered_by_wildcard(domain, whitelist):
#     for allowed in whitelist:
#         if allowed.startswith('*.'):
#             base = allowed[2:].lower()
#             if domain == base or domain.endswith('.' + base):
#                 return True
#     return False

# def is_covered(entry, others):
#     for other in others:
#         if other == entry:
#             continue
#         if other.startswith('*.'):
#             base = other[2:]
#             if entry == base or entry.endswith('.' + base):
#                 return True
#     return False

# # Main merge logic
# merged = set(base_set)
# added_domains = set(base_set)

# print(f"Base entries: {len(base_set)}, New seen: {len(new_set)}")

# for d in sorted(new_set):
#     if d in added_domains or covered_by_wildcard(d, added_domains):
#         continue

#     choice = input(f"Add '{d}'? [y/N/w]: ")
#     if choice.lower() == 'y':
#         added_domains.add(d)
#         merged.add(d)
#     elif choice.lower() == 'w':
#         parts = d.split('.')
#         for i in range(len(parts) - 2, -1, -1):
#             wc = '*.' + '.'.join(parts[i:])
#             yn = input(f"  Add wildcard '{wc}'? [y/N]: ")
#             if yn.lower() == 'y':
#                 merged.add(wc)
#                 added_domains.add(wc)
#                 # Now ask if user wants to add base (non-wildcard) too
#                 base_domain = wc[2:]
#                 if base_domain not in added_domains:
#                     yn_base = input(f"  Wildcard added. Also add base '{base_domain}'? [y/N]: ")
#                     if yn_base.lower() == 'y':
#                         merged.add(base_domain)
#                         added_domains.add(base_domain)
#                 break

# # Second pass: wildcard exists, but base doesn't → ask
# for entry in sorted(merged):
#     if entry.startswith('*.'):
#         base = entry[2:]
#         if base not in merged:
#             yn = input(f"Wildcard '{entry}' exists, but base '{base}' is not in list. Add it? [y/N]: ")
#             if yn.lower() == 'y':
#                 merged.add(base)

# # Remove redundant entries
# filtered = set()
# for entry in merged:
#     others = merged - {entry}
#     if not is_covered(entry, others):
#         filtered.add(entry)

# # Write final list
# with open(BASE, 'w') as f:
#     json.dump(sorted(filtered), f, indent=2)

# print(f"Merged {len(filtered)} entries → {BASE}")
