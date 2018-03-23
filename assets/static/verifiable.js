// The following is a subset with minor modifications of code found in:
// https://github.com/continusec/verifiabledatastructures/

// Original NOTICE:
// These tools were originally written by Adam Eijdenberg <adam@continusec.com>.

function IsPow2(k) {
    while (((k % 2) == 0) && (k > 1)) {
        k /= 2;
    }
    return (k == 1);
}

function lsb(x) {
    return (x & 1) == 1;
}

function DrawNodeResult(ctx, leftX, leftY, rightX, rightY, hash, range, special, inverted, noStyle) {
    var f = inverted ? 1 : -1;

    ctx.save();
    ctx.translate(0, NODE_HEIGHT * 0.5); // so that we are on the centreline

    ctx.beginPath();
    ctx.moveTo(leftX * NODE_WIDTH, f * ((leftY * NODE_HEIGHT) + (leftY == 0 ? NODE_OFFSET*2 : NODE_BIG_OFFSET)));
    ctx.lineTo(leftX * NODE_WIDTH, f * (0.5 + Math.max(leftY, rightY)) * NODE_HEIGHT);
    ctx.lineTo(rightX * NODE_WIDTH, f * (0.5 + Math.max(leftY, rightY)) * NODE_HEIGHT);
    ctx.lineTo(rightX * NODE_WIDTH, f * ((rightY * NODE_HEIGHT) + (rightY == 0 ? NODE_OFFSET*2 : NODE_BIG_OFFSET)));
    ctx.moveTo((leftX + rightX) * NODE_WIDTH / 2.0, f * (0.5 + Math.max(leftY, rightY)) * NODE_HEIGHT);
    ctx.lineTo((leftX + rightX) * NODE_WIDTH / 2.0, f * (1.0 - (NODE_BIG_OFFSET * 1.0 / NODE_HEIGHT) + Math.max(leftY, rightY)) * NODE_HEIGHT);
    ctx.stroke();

    ctx.translate((((leftX + rightX) / 2.0) - 0.5) * NODE_WIDTH, f * ((inverted ? 0.5 : 1.5) + Math.max(leftY, rightY)) * NODE_HEIGHT);

    DrawHashBox(ctx, hash, range, special, noStyle);
    ctx.restore();
}


function DrawConsistencyProofInContext(ctx, first_size, first_hash, second_size, second_hash, proof, noStyle) {
    var actualPaths = SubProof(first_size, 0, second_size, true);
    if (IsPow2(first_size)) {
        var proof2 = [first_hash];
        var paths2 = [[0, first_size]];
        for (var i = 0; i < proof.length; i++) {
            proof2.push(proof[i]);
            paths2.push(actualPaths[i]);
        }
        proof = proof2;
        actualPaths = paths2;
    }

    var proofToOrigIndex = {};
    for (var i = 0; i < actualPaths.length; i++) {
        proofToOrigIndex[proof[i]] = i;
    }
    var sortedProofs = proof.slice(0);
    sortedProofs.sort(function (a, b) {
        return actualPaths[proofToOrigIndex[a]][0] - actualPaths[proofToOrigIndex[b]][0];
    });

    var proofToUIIndex = {};
    for (var i = 0; i < sortedProofs.length; i++) {
        proofToUIIndex[sortedProofs[i]] = i + 0.5;
    }

    ctx.save();

    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(0, 0.5 * NODE_HEIGHT);
    ctx.lineTo(NODE_WIDTH * proof.length, 0.5 * NODE_HEIGHT);
    ctx.stroke();

    ctx.restore();

    var fn = first_size - 1;
    var sn = second_size - 1;
    while (lsb(fn)) {
        fn >>= 1;
        sn >>= 1;
    }

    var fr = proof[0];
    var fx = proofToUIIndex[proof[0]];
    var fy = 0;

    var sr = proof[0];
    var sx = proofToUIIndex[proof[0]];
    var sy = 0;

    for (var i = 1; i < proof.length; i++) {
        var ourUIIndex = proofToUIIndex[proof[i]];
        if ((fn == sn) || lsb(fn)) {
            fr = nodeMerkleTreeHash(proof[i], fr);
            DrawNodeResult(ctx, ourUIIndex, 0, fx, fy, fr, null, (fr == first_hash) ? "first_hash" : "calculated", true, noStyle);
            fx = (ourUIIndex + fx) / 2.0;
            fy += 1;

            sr = nodeMerkleTreeHash(proof[i], sr);
            DrawNodeResult(ctx, ourUIIndex, 0, sx, sy, sr, null, (sr == second_hash) ? "second_hash" : "calculated", false, noStyle);
            sx = (ourUIIndex + sx) / 2.0;
            sy += 1;

            while (!((fn == 0) || lsb(fn))) {
                fn >>= 1;
                sn >>= 1;
            }
        } else {
            sr = nodeMerkleTreeHash(sr, proof[i]);
            DrawNodeResult(ctx, sx, sy, ourUIIndex, 0, sr, null, (sr == second_hash) ? "second_hash" : "calculated", false, noStyle);
            sx = (ourUIIndex + sx) / 2.0;
            sy += 1;
        }
        fn >>= 1;
        sn >>= 1;
    }

    for (var i = 0; i < sortedProofs.length; i++) {
        ctx.save();
        ctx.translate(i * NODE_WIDTH, 0);
        DrawHashBox(ctx, sortedProofs[i], actualPaths[proofToOrigIndex[sortedProofs[i]]], (sortedProofs[i] == first_hash) ? "first_hash" : "consistency", noStyle);
        ctx.restore();
    }
}

function ReallyCalcK(n) {
    var k = 1;
    while ((k << 1) < n) {
        k <<= 1;
    }
    return k;
}

function nodeMerkleTreeHash(l, r) {
    return sha256(String.fromCharCode(1) + l + r);
}

function SubProof(m, start_n, end_n, b) {
    var n = end_n - start_n;
    if (m == n) {
        if (b) {
            return [];
        } else {
            return [[start_n, end_n]];
        }
    } else {
        var k = ReallyCalcK(n);
        if (m <= k) {
            var rv = SubProof(m, start_n, start_n+k, b);
            rv.push([start_n + k, end_n]);
            return rv;
        } else {
            var rv = SubProof(m-k, start_n+k, end_n, false);
            rv.push([start_n, start_n + k]);
            return rv;
        }
    }
}

function DrawConsistencyProof(c, first_size, first_hash, second_size, second_hash, proof) {
    var pl = proof.length;
    if (IsPow2(first_size)) {
        pl++;
    }

    var fn = first_size - 1;
    var sn = second_size - 1;
    while (lsb(fn)) {
        fn >>= 1;
        sn >>= 1;
    }
    var fy = 0;
    var sy = 0;
    for (var i = 1; i < pl; i++) {
        if ((fn == sn) || lsb(fn)) {
            fy += 1;
            sy += 1;
            while (!((fn == 0) || lsb(fn))) {
                fn >>= 1;
                sn >>= 1;
            }
        } else {
            sy += 1;
        }
        fn >>= 1;
        sn >>= 1;
    }

    // Now we know width and height...
    var desWidth = NODE_WIDTH * pl;
    var desHeight = (sy + 1 + fy) * NODE_HEIGHT;

    var canvas = c[0];

    var R = window.devicePixelRatio;

    canvas.width = R * desWidth;
    canvas.height = R * desHeight;

    c.css({
        width: desWidth,
        height: desHeight,
    });

    var ctx = canvas.getContext("2d");
    ctx.scale(R, R);

    ctx.translate(0, sy * NODE_HEIGHT);

    DrawConsistencyProofInContext(ctx, first_size, first_hash, second_size, second_hash, proof, false);
}

function binaryArrayToString(d) {
    var rv = "";
    for (var j = 0; j < d.length; j++) {
        rv += String.fromCharCode(d[j]);
    }
    return rv;
}

function DrawHashBox(ctx, hash, range, special, noStyle) {
	DrawBox(ctx, btoa(hash), range, special, noStyle)
}

function DrawBox(ctx, hash, range, special, noStyle) {
	var no = NODE_OFFSET;
	if (range == null) {
		no = NODE_BIG_OFFSET;
	}
	if (noStyle !== true) { // set to true when drawing splash screen
		ctx.fillStyle = COLORS[special];
		ctx.fillRect(no, no, NODE_WIDTH - (no * 2), NODE_HEIGHT - (no * 2));
	}
	ctx.strokeRect(no, no, NODE_WIDTH - (no * 2), NODE_HEIGHT - (no * 2));
	ctx.textAlign = "center";
	if (noStyle !== true) {
		ctx.fillStyle = "black";
	}
	if (range == null) {
		ctx.fillText(hash, NODE_WIDTH / 2, (NODE_HEIGHT / 2) + 3);
	} else {
		ctx.fillText(hash, NODE_WIDTH / 2, (NODE_HEIGHT / 2) - 2);
		if ((range[0] + 1) == range[1]) {
			ctx.fillText("Leaf hash for entry: " + range[0], NODE_WIDTH / 2, (NODE_HEIGHT / 2) + 12);
		} else {
			ctx.fillText("Tree hash for entries: " + range[0] + " - " + (range[1] - 1), NODE_WIDTH / 2, (NODE_HEIGHT / 2) + 12);
		}
	}
}

function sha256(b) {
    var shaObj = new jsSHA("SHA-256", "BYTES");
    shaObj.update(b);
    return shaObj.getHash("BYTES");
}

function array_atob(a) {
    var rv = [];
    for (var i = 0; i < a.length; i++) {
        rv.push(atob(a[i]));
    }
    return rv;
}

function leafinput_atob(a) {
    var rv = [];
    for (var i = 0; i < a.length; i++) {
        rv.push(atob(a[i].leaf_input));
    }
    return rv;
}

function leafMerkleTreeHash(b) {
    return sha256(String.fromCharCode(0) + b);
}

function DrawTree(c, startIdx, endIdx, verifiableEntries) {
    // Now we know width and height...
    var desWidth = NODE_WIDTH * endIdx;
    var treeHeight = 1 + Path(0, 0, endIdx).length;
    var desHeight = treeHeight * NODE_HEIGHT;

    var canvas = c[0];

    R = window.devicePixelRatio;

    canvas.width = R * desWidth;
    canvas.height = R * desHeight;

    c.css({
        width: desWidth,
        height: desHeight,
    });

    ctx = canvas.getContext("2d");
    ctx.scale(R, R);

    ctx.translate(0, (treeHeight - 1) * NODE_HEIGHT);

    ctx.save();

    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(0, 0.5 * NODE_HEIGHT);
    ctx.lineTo(NODE_WIDTH * endIdx, 0.5 * NODE_HEIGHT);
    ctx.stroke();
    ctx.restore();

    var cache = {};

    for (var i = 0; i < endIdx; i++) {
        var key = i + "-" + (i + 1);
        cache[key] = leafMerkleTreeHash(verifiableEntries[i]);
    }

    var lastCenter = -1
    for (var i = 0, skip = 2; i < (treeHeight - 1); i++, skip *= 2) {
        for (var j = 0; j < endIdx; j += skip) {
            var left = j + "-" + (j + (skip * 0.5));
            var right = (j + (skip * 0.5)) + "-" + Math.min(j + skip, endIdx);
            if (left in cache && right in cache) {
                var key = j + "-" + Math.min(j + skip, endIdx);
                r = nodeMerkleTreeHash(cache[left], cache[right]);
                cache[key] = r;

                var ourLeft = j + (skip * 0.25);
                var ourRight = j + (skip * 0.75);

                if ((j + skip) >= endIdx) {
                    if (lastCenter != -1) {
                        ourRight = lastCenter;
                    }
                    lastCenter = (ourLeft + ourRight) * 0.5;
                }
                DrawNodeResult(ctx,
                    ourLeft, i,
                    ourRight, i,
                    r, null, "calculated", false);
            } else {
                var thisCenter = j + (skip * 0.5);
                if ((j + skip) >= endIdx) {
                    if (lastCenter != -1) {
                        thisCenter = lastCenter;
                    } else {
                        thisCenter = endIdx - 0.5;
                    }
                    lastCenter = thisCenter;
                }
                DrawNoResult(ctx, thisCenter, i, false);
            }
        }
    }

    for (var i = 0; i < endIdx; i++) {
        var key = i + "-" + (i + 1);
        ctx.save();
        ctx.translate(i * NODE_WIDTH, 0);
        DrawHashBox(ctx, cache[key], [i, i + 1], "leaf_input");
        ctx.restore();
    }
}

function Path(m, start_n, end_n) {
	var n = end_n - start_n;
	if (n == 1) {
		return [];
	} else {
		var k = ReallyCalcK(n);
		if (m < k) {
			var rv = Path(m, start_n, start_n+k);
			rv.push([start_n + k, end_n]);
			return rv;
		} else {
			var rv = Path(m-k, start_n+k, end_n);
			rv.push([start_n, start_n + k]);
			return rv;
		}
	}
}
