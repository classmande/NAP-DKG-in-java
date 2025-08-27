package org.example.napdkg.core;

import org.example.napdkg.client.PbbClient;
import org.example.napdkg.util.DkgContext;

// Container class for storing the context information of the DKG. 
public class PartyContext {
    public final int id, n, t, fa;
    public final DkgContext ctx;
    public final PbbClient pbb;

    // YOUR OWN keypair:
    public DhKeyPair ephKey;

    // PUBLIC ephemeral keys of _all_ parties, indexed by party-ID:
    // (you only store the public ECPoint + proof part, not their secrets)
    public PublicKeysWithProofs[] allEphPubs;

    public PartyContext(int id, DkgContext ctx, PbbClient pbb, int n, int t, int fa) {
        this.id = id;
        this.ctx = ctx;
        this.n = n;
        this.t = t;

        this.fa = fa;
        this.pbb = pbb;
        this.allEphPubs = new PublicKeysWithProofs[n];
    }
}
