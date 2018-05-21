
NODE_WIDTH = 320;
NODE_HEIGHT = 60;
NODE_OFFSET = 10;
NODE_BIG_OFFSET = 15;
COLORS = {
    "consistency": "LightCoral",
    "inclusion": "LightCoral",
    "calculated": "DarkKhaki",
    "first_hash": "ALICEBLUE",
    "second_hash": "ALICEBLUE",
    "tree_hash": "ALICEBLUE",
    "leaf_input": "#48C9B0",
};

function createRFC6962MerkleTreeLeafFromObjectHash(timestamp, objectHash) {
    // version 0x00
    // MerkleLeafType 0x00
    // Timestamp - big-endian, 8 bytes
    // LogEntryType - 0x0801
    // Object hash : 32 bytes
    // Extensions: 0x0000

    var rv = new Uint8Array(1 + 1 + 8 + 2 + 32 + 2); // docs claim inited to 0

    // Set timestamp
    var curTS = timestamp
    for (var i = 7; i >= 0; i--) {
        rv[1 + 1 + i] = curTS % 256;
        curTS = (curTS - (curTS % 256)) / 256; // because >> 8 doesn't work for big numbers in Javascript??
    }

    // Set LogEntryType
    rv[1 + 1 + 8] = 0x80;
    rv[1 + 1 + 8 + 1] = 0x01;

    // Copy object hash
    for (var i = 0; i < 32; i++) {
        rv[1 + 1 + 8 + 2 + i] = objectHash.charCodeAt(i);
    }

    return binaryArrayToString(rv);
}

function restCall(path, data, success, failure) {
    var req = new XMLHttpRequest();
    req.onload = function (evt) {
        switch (req.status) {
            case 200:
                var obj = JSON.parse(binaryArrayToString(new Uint8Array(req.response)));
                success(obj, req);
                break;
            case 400:
                failure("bad request");
                break;
            case 403:
                failure("unauthorized");
                break;
            case 404:
                failure("not found");
                break;
            default:
                failure("internal error");
        }
    };
    req.onerror = function (evt) {
        failure("network error");
    };
    req.open("GET", path, true);
    req.responseType = "arraybuffer";
    req.send(data);
}

function doGetEntries(first, lastExclusive) {
    restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-entries?start=" + first + "&end=" + (lastExclusive - 1), null, function (result) {
        var s = "";
        for (var i = 0; i < result.entries.length; i++) {
            s += atob(result.entries[i].extra_data) + "\n";
        }

        $("#get_entries_result").text(s);

        /* don't draw if more than 50, since about there hits a 32000 pixel limit for width in Chrome */
        if ((result.entries.length <= 50) && (first == 0)) {
            DrawTree($("#get_entries_diagram"), first, lastExclusive, leafinput_atob(result.entries));
        }
    }, function (reason) {
        $("#get_entries_result").text("error: " + reason);
    });
}

$(function () {
    $("#get_sth").click(function (e) {
        e.preventDefault();
        restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-sth?tree_size=" + Number($("#get_sth_tree_size").val()), null, function (result) {
            var s = "";
            s += "tree size: " + result.tree_size + "\n";
            s += "root hash: " + result.sha256_root_hash + "\n";
            $("#get_sth_result").text(s);
        }, function (reason) {
            $("#get_sth_result").text("error: " + reason);
        });
        return false;
    });
    $("#get_consistency").click(function (e) {
        e.preventDefault();
        restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-sth?tree_size=" + Number($("#get_consistency_first").val()), null, function (first) {
            restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-sth?tree_size=" + Number($("#get_consistency_second").val()), null, function (second) {
                restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-sth-consistency?first=" + Number(first.tree_size) + "&second=" + Number(second.tree_size), null, function (result) {
                    var s = "";
                    s += "first tree size: " + first.tree_size + "\n";
                    s += "first root hash: " + first.sha256_root_hash + "\n";
                    s += "\n";
                    s += "second tree size: " + second.tree_size + "\n";
                    s += "second root hash: " + second.sha256_root_hash + "\n";
                    s += "\n";

                    s += "consistency audit path:\n\n";
                    for (var i = 0; i < result.consistency.length; i++) {
                        s += result.consistency[i] + "\n";
                    }

                    $("#get_consistency_result").text(s);

                    DrawConsistencyProof($("#get_consistency_diagram"), first.tree_size, atob(first.sha256_root_hash), second.tree_size, atob(second.sha256_root_hash), array_atob(result.consistency));
                }, function (reason) {
                    $("#get_consistency_result").text("error: " + reason);
                });
            }, function (reason) {
                $("#get_consistency_result").text("error: " + reason);
            });
        }, function (reason) {
            $("#get_consistency_result").text("error: " + reason);
        });
        return false;
    });
    $("#get_entries").click(function (e) {
        e.preventDefault();
        var last = Number($("#get_entries_second").val());
        if (last == 0) {
            restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-sth", null, function (result) {
                doGetEntries(Number($("#get_entries_first").val()), result.tree_size);
            }, function (reason) {
                $("#get_entries_result").text("error: " + reason);
            });
        } else {
            doGetEntries(Number($("#get_entries_first").val()), last);
        }
    });
    $("#inclusion_proof").click(function (e) {
        e.preventDefault();
        var jsonValue = $("#inclusion_proof_input").val();
        var asObj = JSON.parse(jsonValue);
        var objectHash = objectHashWithRedaction(JSON.parse(jsonValue), '');
        restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-sth?tree_size=" + Number($("#inclusion_proof_tree_size").val()), null, function (sth) {
            restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-objecthash?hash=" + encodeURIComponent(btoa(objectHash)), null, function (sct) {
                var mtlInput = createRFC6962MerkleTreeLeafFromObjectHash(sct.timestamp, objectHash);
                var leafHash = leafMerkleTreeHash(mtlInput);
                restCall("https://verifiable-logs.apps.y.cld.gov.au/dataset/b718232a-bc8d-49c0-9c1f-33c31b57cd88/ct/v1/get-proof-by-hash?hash=" + encodeURIComponent(btoa(leafHash)) + "&tree_size=" + sth.tree_size, null, function (inclusionProof) {
                    var s = "";
                    s += "calculated object hash: " + btoa(objectHash) + "\n";
                    s += "retrieved sct timestamp: " + sct.timestamp + "\n";
                    s += "calculated merkle tree leaf hash: " + btoa(leafHash) + "\n";
                    s += "\n";
                    s += "leaf index: " + inclusionProof.leaf_index + "\n";
                    s += "tree size: " + sth.tree_size + "\n";
                    s += "\n";
                    s += "inclusion audit path:\n\n";
                    for (var i = 0; i < inclusionProof.audit_path.length; i++) {
                        s += inclusionProof.audit_path[i] + "\n";
                    }

                    $("#inclusion_proof_result").text(s);

                    DrawInclusionProof($("#inclusion_proof_diagram"), inclusionProof.leaf_index, leafHash, sth.tree_size, atob(sth.sha256_root_hash), array_atob(inclusionProof.audit_path));
                }, function (reason) {
                    $("#inclusion_proof_result").text("error: " + reason);
                });
            }, function (reason) {
                $("#inclusion_proof_result").text("error: " + reason);
            });
        }, function (reason) {
            $("#inclusion_proof_result").text("error: " + reason);
        });
    });
});