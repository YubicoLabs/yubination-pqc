window.APP = {
  name: "Secure App",
  badge: "ML-DSA required",
  rule: "Only admits credentials signed with FIPS 204 ML-DSA. Uses a client-specific browser flow.",
  requirement: "a post-quantum (ML-DSA) passkey",
  clientId: "app-secure",
  authority: "http://localhost:8085/realms/pq",
  redirectUri: "http://localhost:8092/",
  accent: "#7a3fd1",
};
