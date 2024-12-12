import dns.resolver

answers = dns.resolver.resolve("google.com", 'NS')
for server in answers:
    print(server.target)