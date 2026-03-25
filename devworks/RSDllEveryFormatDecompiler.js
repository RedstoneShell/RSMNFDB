/*
    Made by RedstoneShell, provided by RedstoneShell Microsoft Not-documented Functions DB
    Copyright (C) 2026 RedstoneShell. All rights reserved
*/

class RSDEFD {
    constructor(arrayBuffer, options = {}) {
        if (typeof GUECMan !== 'undefined') {
            GUECMan.ConnectToClass(this);
        }
        this.buffer = arrayBuffer;
        this.view = new DataView(arrayBuffer);
        this.bytes = new Uint8Array(arrayBuffer);
        this.is64bit = false;
        this.tlsentptaddr = 0;
        this.imageBase = 0n;
        this.options = {
            verbose: false,
            extractResources: true,
            detectForwarders: true,
            minimalNoise: true,
            ...options
        };
        
        this.result = {
            success: false,
            error: null,
            tables: [],  // Tabel list for UI
            summary: {}, // Short summary
            raw: {}      // Raw data (for export)
        };
    }

    /**
     * Main method to scan PE/DLL files
     * @returns {Object} - Result from tables[] for UI
     */
    async scan() {
        try {
            this.report = {
                fileInfo: {},
                dosHeader: {},
                ntHeaders: {},
                sections: [],
                exports: { functions: [], forwarders: [], byOrdinal: [] },
                imports: [],
                delayedImports: [],
                boundImports: [],
                resources: { version: null, manifest: null, icons: [], strings: [], other: [] },
                tls: null,
                exceptions: [],
                relocations: [],
                debug: null,
                securityCookie: null,
                controlFlowGuard: null
            };
            if (!this.checkMZ()) throw new Error("Not a valid PE file");
            this.parseDOSHeader();
            this.parseNTHeaders();
            console.log("NT Headers:", this.report.ntHeaders);
            console.log("File size:", this.report.fileInfo.size);
            this.parseSections();
            await this.collectTables();
            this.result.success = true;
            this.result.summary = this.buildSummary();
            this.result.raw = this.report;
            
            return this.result;
            
        } catch (error) {
            this.result.success = false;
            this.result.error = error.message;
            return this.result;
        }
    }

    async collectTables() {
        this.result.tables = [];
        try { this.scanForwardersOnly(); } catch(e) { console.warn("scanForwardersOnly failed:", e.message); }
        try { this.scanImports(); } catch(e) { console.warn("scanImports failed:", e.message); }
        try { this.scanDelayedImports(); } catch(e) { console.warn("scanDelayedImports failed:", e.message); }
        try { this.scanBoundImports(); } catch(e) { console.warn("scanBoundImports failed:", e.message); }
        if (this.options.extractResources) {
            try { this.scanResources(); } catch(e) { console.warn("scanResources failed:", e.message); }
        }
        try { this.scanTLS(); } catch(e) { console.warn("scanTLS failed:", e.message); }
        try { await this.scanTextSection(); } catch(e) { console.warn("scanTextSection failed:", e.message); }
        try { this.scanExceptions(); } catch(e) { console.warn("scanExceptions failed:", e.message); }
        try { this.scanRelocations(); } catch(e) { console.warn("scanRelocations failed:", e.message); }
        try { this.scanDebug(); } catch(e) { console.warn("scanDebug failed:", e.message); }
        try { this.scanSecurityCookie(); } catch(e) { console.warn("scanSecurityCookie failed:", e.message); }
        try { this.scanControlFlowGuard(); } catch(e) { console.warn("scanControlFlowGuard failed:", e.message); }
        try { this.scanApiSetSchema(); } catch(e) { console.warn("scanApiSetSchema failed:", e.message); }
        this.result.tables.push({
            title: "File Information",
            icon: "file",
            columns: ["Property", "Value"],
            rows: [
                ["File Name", this.report.fileInfo.name || "Unknown"],
                ["File Size", `${this.report.fileInfo.size} bytes`],
                ["MD5", this.report.fileInfo.md5 || "N/A"],
                ["Architecture", this.report.ntHeaders.machine || "Unknown"],
                ["Image Base", this.report.ntHeaders.imageBase || "N/A"],
                ["Entry Point", this.report.ntHeaders.entryPoint || "N/A"]
            ]
        });
        
        // Table 2: Security Features
        this.result.tables.push({
            title: "Security Features",
            icon: "shield",
            columns: ["Feature", "Status"],
            rows: [
                ["ASLR", this.report.ntHeaders.aslr ? "✅ Enabled" : "❌ Disabled"],
                ["DEP", this.report.ntHeaders.dep ? "✅ Enabled" : "❌ Disabled"],
                ["SafeSEH", this.report.ntHeaders.safeseh ? "✅ Enabled" : "❌ Disabled"],
                ["Control Flow Guard", this.report.controlFlowGuard?.enabled ? "✅ Enabled" : "❌ Disabled"],
                ["Security Cookie", this.report.securityCookie?.found ? "✅ Present" : "❌ Not found"]
            ]
        });
        
        if (this.report.exports.forwarders.length > 0) {
            const hasNames = this.report.exports.forwarders.some(f => f.name && f.name !== `#${f.ordinal}`);
            
            this.result.tables.push({
                title: `↪️ Forwarders (${this.report.exports.forwarders.length})`,
                icon: "forward",
                columns: hasNames ? ["Name", "Ordinal", "Forwards To", "Target DLL", "Target Function"] 
                                 : ["Ordinal", "Forwards To", "Target DLL", "Target Function"],
                rows: this.report.exports.forwarders.map(f => {
                    const displayName = f.name && f.name !== `#${f.ordinal}` ? f.name : null;
                    const row = [
                        f.ordinal,
                        f.forwardTo,
                        f.dll || "Unknown",
                        f.function || "Unknown"
                    ];
                    if (hasNames && displayName) {
                        row.unshift(displayName);
                    }
                    return row;
                })
            });
        }
        
        // Table 5: Imports
        if (this.report.imports.length > 0) {
            const importRows = [];
            for (const imp of this.report.imports) {
                importRows.push([imp.dllName, `${imp.functions.length} functions`, ""]);
                for (const func of imp.functions.slice(0, 40)) {
                    importRows.push(["", func.name || `Ordinal ${func.ordinal}`, func.hint ? `hint: ${func.hint}` : ""]);
                }
                if (imp.functions.length > 10) {
                    importRows.push(["", `... and ${imp.functions.length - 10} more`, ""]);
                }
            }
            this.result.tables.push({
                title: `Imports (${this.report.imports.length} DLLs)`,
                icon: "import",
                columns: ["DLL Name", "Function", "Hint"],
                rows: importRows
            });
        }
        
        // Table 6: Delayed Imports
        if (this.report.delayedImports.length > 0) {
            this.result.tables.push({
                title: `Delayed Imports (${this.report.delayedImports.length})`,
                icon: "delay",
                columns: ["DLL Name", "Timestamp"],
                rows: this.report.delayedImports.map(d => [d.dllName, d.timeDateStamp || "N/A"])
            });
        }
        
        // Table 7: Bound Imports
        if (this.report.boundImports.length > 0) {
            this.result.tables.push({
                title: `Bound Imports (${this.report.boundImports.length})`,
                icon: "bound",
                columns: ["DLL Name", "Timestamp"],
                rows: this.report.boundImports.map(b => [b.dllName, b.timeDateStamp || "N/A"])
            });
        }
        
        // Table 8: Sections
        if (this.report.sections.length > 0) {
            this.result.tables.push({
                title: `Sections (${this.report.sections.length})`,
                icon: "sections",
                columns: ["Name", "Virtual Address", "Virtual Size", "Raw Size", "Characteristics"],
                rows: this.report.sections.map(s => [
                    s.name,
                    `0x${s.virtualAddress.toString(16)}`,
                    `0x${s.virtualSize.toString(16)}`,
                    `0x${s.sizeOfRawData.toString(16)}`,
                    s.characteristics
                ])
            });
        }
        
        // Table 9: Resources (VERSION INFO)
        if (this.report.resources.version) {
            this.result.tables.push({
                title: "Version Information",
                icon: "info",
                columns: ["Property", "Value"],
                rows: [
                    ["Type", this.report.resources.version.type],
                    ["Size", `${this.report.resources.version.size} bytes`]
                ]
            });
        }
        
        // Table 10: TLS (Thread Local Storage)
        if (this.report.tls) {
            this.result.tables.push({
                title: "Thread Local Storage",
                icon: "tls",
                columns: ["Property", "Value"],
                rows: [
                    ["Start Address", this.report.tls.startAddressOfRawData],
                    ["End Address", this.report.tls.endAddressOfRawData],
                    ["Index Address", this.report.tls.addressOfIndex],
                    ["Callbacks Address", this.report.tls.addressOfCallbacks]
                ]
            });
        }
        
        // Table 11: Exception handlers
        if (this.report.exceptions.length > 0) {
            this.result.tables.push({
                title: `Exception Handlers (${this.report.exceptions.length})`,
                icon: "exception",
                columns: ["Begin Address", "End Address", "Unwind Info"],
                rows: this.report.exceptions.slice(0, 3000).map(e => [
                    e.beginAddress,
                    e.endAddress,
                    e.unwindInfoAddress || "N/A"
                ])
            });
            if (this.report.exceptions.length > 3000) {
                this.result.tables[this.result.tables.length - 1].rows.push([
                    `... and ${this.report.exceptions.length - 20} more`,
                    "",
                    ""
                ]);
            }
        }
        
        // Table 12: Relocations
        if (this.report.relocations.length > 0) {
            const totalRelocs = this.report.relocations.reduce((sum, r) => sum + r.entries.length, 0);
            this.result.tables.push({
                title: `Relocations (${totalRelocs} entries)`,
                icon: "reloc",
                columns: ["Page RVA", "Entries Count", "Types"],
                rows: this.report.relocations.slice(0, 30).map(r => [
                    `0x${r.pageRVA.toString(16)}`,
                    r.entries.length,
                    [...new Set(r.entries.map(e => e.typeName))].join(", ")
                ])
            });
            if (this.report.relocations.length > 10) {
                this.result.tables[this.result.tables.length - 1].rows.push([
                    `... and ${this.report.relocations.length - 10} more pages`,
                    "",
                    ""
                ]);
            }
        }
        
        // Table 13: Debug (PDB)
        if (this.report.debug && this.report.debug.length > 0) {
            this.result.tables.push({
                title: "Debug Information",
                icon: "debug",
                columns: ["Type", "PDB Path", "GUID", "Age"],
                rows: this.report.debug.map(d => [
                    d.type,
                    d.pdbName || "N/A",
                    d.guid || "N/A",
                    d.age || "N/A"
                ])
            });
        }
        
        // Table 14: DOS HEADER
        if (this.options.verbose) {
            this.result.tables.push({
                title: "DOS Header",
                icon: "dos",
                columns: ["Field", "Value"],
                rows: Object.entries(this.report.dosHeader).map(([k, v]) => [k, v])
            });
        }
        
        // Table 15: NT HEADERS
        if (this.options.verbose) {
            const ntRows = [];
            for (const [k, v] of Object.entries(this.report.ntHeaders)) {
                if (typeof v !== 'object') {
                    ntRows.push([k, String(v)]);
                }
            }
            this.result.tables.push({
                title: "NT Headers",
                icon: "nt",
                columns: ["Field", "Value"],
                rows: ntRows
            });
        }
    }

    checkMZ() {
        return this.view.getUint16(0, true) === 0x5A4D;
    }

    scanForwardersOnly() {
        const dataDir = this.getDataDirectory(0);
        
        let foundInExportTable = false;
        
        if (dataDir.virtualAddress !== 0 && dataDir.size !== 0) {
            const exportOffset = this.rvaToOffset(dataDir.virtualAddress);
            if (exportOffset !== -1) {
                const nameRVA = this.view.getUint32(exportOffset + 12, true);
                const numberOfFunctions = this.view.getUint32(exportOffset + 20, true);
                const addressOfFunctionsRVA = this.view.getUint32(exportOffset + 28, true);
                const addressOfNamesRVA = this.view.getUint32(exportOffset + 32, true);
                const addressOfNameOrdinalsRVA = this.view.getUint32(exportOffset + 36, true);
                
                // Отримуємо ім'я DLL
                const nameOffset = this.rvaToOffset(nameRVA);
                if (nameOffset !== -1) {
                    let nameBytes = [];
                    for (let i = 0; i < 256 && nameOffset + i < this.bytes.length; i++) {
                        const byte = this.bytes[nameOffset + i];
                        if (byte === 0) break;
                        nameBytes.push(byte);
                    }
                    this.report.exports.dllName = new TextDecoder('utf-8').decode(new Uint8Array(nameBytes));
                }
                
                // Будуємо мапу імен по ординалах
                const namesOffset = this.rvaToOffset(addressOfNamesRVA);
                const ordinalsOffset = this.rvaToOffset(addressOfNameOrdinalsRVA);
                const nameMap = new Map();
                
                if (namesOffset !== -1 && ordinalsOffset !== -1) {
                    const numberOfNames = this.view.getUint32(exportOffset + 24, true);
                    for (let i = 0; i < numberOfNames; i++) {
                        const nameOrdinal = this.view.getUint16(ordinalsOffset + i * 2, true);
                        const nameRVA_ = this.view.getUint32(namesOffset + i * 4, true);
                        const nameOffset_ = this.rvaToOffset(nameRVA_);
                        if (nameOffset_ !== -1) {
                            let nameBytes = [];
                            for (let j = 0; j < 256 && nameOffset_ + j < this.bytes.length; j++) {
                                const byte = this.bytes[nameOffset_ + j];
                                if (byte === 0) break;
                                nameBytes.push(byte);
                            }
                            const name = new TextDecoder('utf-8').decode(new Uint8Array(nameBytes));
                            nameMap.set(nameOrdinal, name);
                        }
                    }
                }
                
                if (numberOfFunctions > 0 && numberOfFunctions < 50000) {
                    const functionsOffset = this.rvaToOffset(addressOfFunctionsRVA);
                    if (functionsOffset !== -1) {
                        for (let i = 0; i < numberOfFunctions; i++) {
                            const funcRVA = this.view.getUint32(functionsOffset + i * 4, true);
                            if (funcRVA === 0) continue;
                            
                            const isForwarder = funcRVA >= dataDir.virtualAddress && 
                                                funcRVA < dataDir.virtualAddress + dataDir.size;
                            
                            if (isForwarder) {
                                const forwardOffset = this.rvaToOffset(funcRVA);
                                if (forwardOffset !== -1) {
                                    let forwardBytes = [];
                                    for (let j = 0; j < 256 && forwardOffset + j < this.bytes.length; j++) {
                                        const byte = this.bytes[forwardOffset + j];
                                        if (byte === 0) break;
                                        forwardBytes.push(byte);
                                    }
                                    const forwardString = new TextDecoder('utf-8').decode(new Uint8Array(forwardBytes));
                                    const [dll, func] = forwardString.split('.');
                                    const name = nameMap.get(i);
                                    
                                    this.report.exports.forwarders.push({
                                        name: name || `#${i}`,
                                        ordinal: i,
                                        rva: funcRVA,
                                        forwardTo: forwardString,
                                        dll: dll,
                                        function: func || forwardString
                                    });
                                    foundInExportTable = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (!foundInExportTable && this.report.exports.forwarders.length === 0) {
            console.log("🔍 Scanning .rdata for forwarder strings...");
            
            const rdataSection = this.report.sections.find(s => s.name === '.rdata');
            if (rdataSection) {
                const startOffset = rdataSection.pointerToRawData;
                const endOffset = startOffset + rdataSection.sizeOfRawData;
                
                let currentOffset = startOffset;
                let ordinalCounter = 0;
                
                while (currentOffset < endOffset) {
                    while (currentOffset < endOffset && this.bytes[currentOffset] === 0) {
                        currentOffset++;
                    }
                    if (currentOffset >= endOffset) break;
                    
                    let strBytes = [];
                    let strOffset = currentOffset;
                    while (strOffset < endOffset && this.bytes[strOffset] !== 0) {
                        strBytes.push(this.bytes[strOffset]);
                        strOffset++;
                    }
                    
                    if (strBytes.length > 0) {
                        const str = new TextDecoder('utf-8').decode(new Uint8Array(strBytes));
                        
                        if (str.includes('.') && (str.includes('kernel32') || str.includes('ntdll') || 
                            str.includes('user32') || str.includes('advapi32') || str.includes('ucrtbase') ||
                            str.match(/^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$/))) {
                            
                            const [dll, func] = str.split('.');
                            
                            const exists = this.report.exports.forwarders.some(f => f.forwardTo === str);
                            if (!exists) {
                                this.report.exports.forwarders.push({
                                    name: str,
                                    ordinal: ordinalCounter++,
                                    rva: rdataSection.virtualAddress + (currentOffset - startOffset),
                                    forwardTo: str,
                                    dll: dll,
                                    function: func || str,
                                    fromRData: true
                                });
                            }
                        }
                    }
                    
                    currentOffset = strOffset + 1;
                }
            }
        }
        
        console.log(`📤 Found ${this.report.exports.forwarders.length} forwarders`);
    }
    
    parseDOSHeader() {
        try {
            const e_lfanew = this.view.getUint32(0x3C, true);
            if (e_lfanew <= 0 || e_lfanew >= this.bytes.length) {
                console.warn("Invalid e_lfanew, setting fallback value 0x80");
                this.report.dosHeader = { e_magic: "MZ", e_lfanew: 0x80 };
            } else {
                this.report.dosHeader = {
                    e_magic: "MZ",
                    e_lfanew
                };
            }
        } catch (err) {
            console.warn("Failed to parse DOS Header, using fallback", err);
            this.report.dosHeader = { e_magic: "MZ", e_lfanew: 0x80 };
        }
    }
    
    parseNTHeaders() {
        const peOffset = this.report.dosHeader.e_lfanew;
        console.log("PE offset:", peOffset.toString(16));
        const machine = this.view.getUint16(peOffset + 4, true);
        this.is64bit = machine === 0x8664;
        const magic = this.view.getUint16(peOffset + 24, true);
        const isPE32Plus = magic === 0x20B;
        this.imageBase = isPE32Plus ?
            this.view.getBigUint64(peOffset + 48, true) :
            BigInt(this.view.getUint32(peOffset + 52, true));
        const dllCharacteristics = this.view.getUint16(peOffset + 94, true);
        this.report.fileInfo.size = this.bytes.length;
        this.report.ntHeaders = {
            machine: this.getMachineName(machine),
            is64bit: this.is64bit,
            imageBase: `0x${this.imageBase.toString(16)}`,
            entryPoint: `0x${this.view.getUint32(peOffset + 40, true).toString(16)}`,
            subsystem: this.getSubsystemName(this.view.getUint16(peOffset + 92, true)),
            aslr: (dllCharacteristics & 0x40) !== 0,
            dep: (dllCharacteristics & 0x100) !== 0,
            safeseh: (dllCharacteristics & 0x40) !== 0,
            controlFlowGuard: (dllCharacteristics & 0x4000) !== 0
        };
        console.log("NT Headers parsed:", this.report.ntHeaders.machine);
    } 
    
    parseSections() {
        const peOffset = this.report.dosHeader.e_lfanew;
        const fileHeaderOffset = peOffset + 4;
        const numberOfSections = this.view.getUint16(fileHeaderOffset + 2, true);
        const sizeOfOptionalHeader = this.view.getUint16(fileHeaderOffset + 16, true);
        const sectionsStart = fileHeaderOffset + 20 + sizeOfOptionalHeader;
        
        for (let i = 0; i < numberOfSections; i++) {
            const offset = sectionsStart + i * 40;
            let nameBytes = [];
            for (let j = 0; j < 8 && offset + j < this.bytes.length; j++) {
                const byte = this.bytes[offset + j];
                if (byte === 0) break;
                nameBytes.push(byte);
            }
            const name = new TextDecoder('utf-8').decode(new Uint8Array(nameBytes));
            
            const virtualSize = this.view.getUint32(offset + 8, true);
            const virtualAddress = this.view.getUint32(offset + 12, true);
            const sizeOfRawData = this.view.getUint32(offset + 16, true);
            const pointerToRawData = this.view.getUint32(offset + 20, true);
            const characteristics = this.view.getUint32(offset + 36, true);
        
            if (virtualSize === 0 && sizeOfRawData === 0) continue;
            
            this.report.sections.push({
                name: name || `.${i}`,
                virtualAddress,
                virtualSize,
                sizeOfRawData,
                pointerToRawData,
                characteristics: "0x" + characteristics.toString(16),
                isExecutable: (characteristics & 0x20000000) !== 0,
                isReadable: (characteristics & 0x40000000) !== 0,
                isWritable: (characteristics & 0x80000000) !== 0,
                isDiscardable: (characteristics & 0x02000000) !== 0
            });
        }
        
        console.log(`Found ${this.report.sections.length} sections:`, this.report.sections.map(s => s.name));
    }

    computeSimpleHash() {
        let hash = 0;
        for (let i = 0; i < Math.min(this.bytes.length, 1024); i++) {
            hash = ((hash << 5) - hash) + this.bytes[i];
            hash |= 0;
        }
        return Math.abs(hash).toString(16);
    }
    
    scanImports() {
        const dataDir = this.getDataDirectory(1);
        if (dataDir.virtualAddress === 0 || dataDir.size === 0) return;
        
        let offset = this.rvaToOffset(dataDir.virtualAddress);
        if (offset === -1 || offset >= this.bytes.length) return;
        
        try {
            while (offset + 20 <= this.bytes.length) {
                const importRVA = this.view.getUint32(offset, true);
                if (importRVA === 0) break;
                
                const nameRVA = this.view.getUint32(offset + 12, true);
                const firstThunkRVA = this.view.getUint32(offset + 16, true);
                
                const nameOffset = this.rvaToOffset(nameRVA);
                let dllName = "Unknown";
                if (nameOffset !== -1) {
                    dllName = this.readString(nameOffset, 256);
                }
                
                const thunkOffset = this.rvaToOffset(firstThunkRVA);
                let functions = [];
                if (thunkOffset !== -1) {
                    functions = this.parseImportThunks(thunkOffset);
                }
                
                if (functions.length > 0) {
                    this.report.imports.push({ dllName, functions });
                }
                
                offset += 20;
            }
            
            console.log(`Found ${this.report.imports.length} imported DLLs`);
            
        } catch (err) {
            console.warn("Error parsing imports:", err);
        }
    }
    
    parseImportThunks(thunkOffset) {
        const functions = [];
        let i = 0;
        
        while (true) {
            let value;
            if (this.is64bit) {
                value = this.view.getBigUint64(thunkOffset + i * 8, true);
                if (value === 0n) break;
            } else {
                value = this.view.getUint32(thunkOffset + i * 4, true);
                if (value === 0) break;
            }
            
            const isOrdinal = (value & 0x80000000) !== 0;
            let name = null;
            let ordinal = null;
            let hint = null;
            
            if (isOrdinal) {
                ordinal = Number(value & 0xFFFF);
            } else {
                const hintNameOffset = this.rvaToOffset(Number(value));
                if (hintNameOffset !== -1) {
                    hint = this.view.getUint16(hintNameOffset, true);
                    name = this.readString(hintNameOffset + 2, 256);
                }
            }
            
            functions.push({ name, ordinal, hint });
            i++;
        }
        
        return functions;
    }
    
    scanDelayedImports() {
        const dataDir = this.getDataDirectory(13);
        if (dataDir.virtualAddress === 0) return;
        
        let offset = this.rvaToOffset(dataDir.virtualAddress);
        if (offset === -1) return;
        
        while (true) {
            const attributes = this.view.getUint32(offset, true);
            if (attributes === 0) break;
            
            const nameRVA = this.view.getUint32(offset + 4, true);
            const nameOffset = this.rvaToOffset(nameRVA);
            const dllName = this.readString(nameOffset, 256);
            
            this.report.delayedImports.push({ dllName });
            offset += 32;
        }
    }
    
    scanBoundImports() {
        const dataDir = this.getDataDirectory(11);
        if (dataDir.virtualAddress === 0) return;
        
        let offset = this.rvaToOffset(dataDir.virtualAddress);
        if (offset === -1) return;
        
        console.log("Bound imports at offset:", offset.toString(16));
        
        let counter = 0;
        while (true) {
            const timeDateStamp = this.view.getUint32(offset, true);
            if (timeDateStamp === 0) break;
            
            const offsetModuleName = this.view.getUint16(offset + 4, true);
            const nameOffset = offset + offsetModuleName;
            
            console.log(`\nBound import ${counter}:`);
            console.log(`  timeDateStamp: ${timeDateStamp}`);
            console.log(`  offsetModuleName: ${offsetModuleName}`);
            console.log(`  nameOffset: 0x${nameOffset.toString(16)}`);
            
            let rawBytes = [];
            for (let i = 0; i < 50 && nameOffset + i < this.bytes.length; i++) {
                rawBytes.push(this.bytes[nameOffset + i].toString(16).padStart(2, '0'));
            }
            console.log(`  Raw bytes: ${rawBytes.join(' ')}`);
            
            let dllNameAscii = "";
            for (let i = 0; i < 256 && nameOffset + i < this.bytes.length; i++) {
                const char = this.bytes[nameOffset + i];
                if (char === 0) break;
                if (char >= 0x20 && char <= 0x7E) {
                    dllNameAscii += String.fromCharCode(char);
                } else {
                    dllNameAscii += `[0x${char.toString(16)}]`;
                }
            }
            console.log(`  ASCII: "${dllNameAscii}"`);
            
            let dllNameUtf16 = "";
            for (let i = 0; i < 256 && nameOffset + i + 1 < this.bytes.length; i += 2) {
                const charCode = this.view.getUint16(nameOffset + i, true);
                if (charCode === 0) break;
                if (charCode >= 0x20 && charCode <= 0x7E) {
                    dllNameUtf16 += String.fromCharCode(charCode);
                } else {
                    dllNameUtf16 += `[0x${charCode.toString(16)}]`;
                }
            }
            console.log(`  UTF-16LE: "${dllNameUtf16}"`);
            
            this.report.boundImports.push({ 
                dllName: dllNameUtf16 || dllNameAscii || `unknown_${counter}`,
                timeDateStamp: timeDateStamp 
            });
            
            const nextOffset = offset + 8 + this.view.getUint16(offset + 6, true) * 8;
            console.log(`  Next offset: 0x${nextOffset.toString(16)}`);
            
            offset = nextOffset;
            counter++;
            
            if (counter > 100) break;
        }
        
        console.log(`\n✅ Found ${this.report.boundImports.length} bound imports`);
    }

    async scanTextSection() {
        const timeoutId = setTimeout(() => {
            console.error("⚠️ SCAN TIMEOUT! Possible infinite loop in extractStringsFromText or disassemble");
        }, 30000);
        console.time("scanTextSection");
        
        const textSection = this.report.sections.find(s => s.name === '.text');
        if (!textSection) {
            console.log("No .text section found");
            console.timeEnd("scanTextSection");
            return;
        }
    
        const textOffset = textSection.pointerToRawData;
        const textSize = textSection.sizeOfRawData;
        
        const virtualAddress = Number(textSection.virtualAddress);
    
        console.log(`📝 .text section: offset 0x${textOffset.toString(16)}, size ${textSize} bytes`);
    
        if (textOffset === 0 || textSize === 0) {
            console.timeEnd("scanTextSection");
            return;
        }
        
        const textBytes = this.bytes.slice(textOffset, textOffset + Math.min(textSize, 20480));
        console.log(`📦 textBytes length: ${textBytes.length}`);
        
        console.time("extractStrings");
        const strings = this.extractStringsFromText(textBytes, virtualAddress);
        console.timeEnd("extractStrings");
        console.log(`📝 Found ${strings.length} string literals in .text`);
        
        console.time("createMask");
        const isCode = new Array(textBytes.length).fill(true);
        for (const str of strings) {
            const offsetInBytes = str.address - virtualAddress;
            for (let j = 0; j < str.length; j++) {
                if (offsetInBytes + j < textBytes.length) {
                    isCode[offsetInBytes + j] = false;
                }
            }
        }
        console.timeEnd("createMask");
        
        console.time("disassembleBlocks");
        let allInstructions = [];
        let i = 0;
        let blockCount = 0;
        
        while (i < textBytes.length) {
            if (!isCode[i]) {
                i++;
                continue;
            }
            
            let blockStart = i;
            while (i < textBytes.length && isCode[i]) {
                i++;
            }
            let blockEnd = i;
            
            if (blockEnd > blockStart) {
                blockCount++;
                const codeBlock = textBytes.slice(blockStart, blockEnd);
                const blockRVA = virtualAddress + blockStart; 
                console.log(`  Block ${blockCount}: offset ${blockStart}, size ${codeBlock.length} bytes`);
                let instructions = this.disassemble(codeBlock, blockRVA);
                instructions = this.filterDataSection(instructions, codeBlock, blockRVA);
                allInstructions.push(...instructions);
            }
        }
        console.timeEnd("disassembleBlocks");
        console.log(`🔧 Disassembled ${allInstructions.length} instructions in ${blockCount} blocks (skipped ${strings.length} strings)`);
        
        let deoptimizedAsm = [];
        let hasFpo = false;
        
        if (allInstructions.length > 0) {
            hasFpo = allInstructions.some(inst => 
                inst.mnemonic === 'push' && 
                (inst.text.includes('rbx') || inst.text.includes('rsi') || inst.text.includes('rdi')) &&
                !inst.text.includes('rbp')
            );
            
            if (hasFpo) {
                console.log("🔧 FPO code detected, running deoptimizer...");
                try {
                    const deoptimizer = new FPODeoptimizer(allInstructions, this.bytes);
                    deoptimizedAsm = deoptimizer.deoptimize();
                    console.log(`✅ Deoptimized to ${deoptimizedAsm.length} ASM lines`);
                } catch (err) {
                    console.error("FPODeoptimizer error:", err);
                }
            }
        }
        
        let cppCode = [];
        
        if (allInstructions.length > 0) {
            try {
                const decompiler = new CppDecompiler(this.bytes, allInstructions);
                decompiler.strings = strings;
                decompiler.imports = this.report.imports;
                
                let decompiledCode = await decompiler.decompile();
                
                if (typeof decompiledCode === 'string') {
                    decompiledCode = decompiledCode.split('\n');
                }
                if (Array.isArray(decompiledCode) && decompiledCode.length > 0) {
                    cppCode = decompiledCode;
                    console.log(`✅ Decompiled to ${cppCode.length} lines of C++`);
                    
                    if (cppCode.length > 0) {
                        this.result.tables.push({
                            title: `⚡ Decompiled C++ Code (${cppCode.length} lines)`,
                            icon: "cpp",
                            columns: ["Line"],
                            rows: cppCode.map(line => [line]),
                            isCpp: true,
                            cppCode: cppCode
                        });
                        console.log(`✅ Added C++ decompilation table`);
                    }
                }
            } catch (err) {
                console.error("CppDecompiler error:", err);
                console.error(err.stack);
            }
        }
    
        if (deoptimizedAsm.length > 0) {
            this.result.tables.push({
                title: `🔧 Deoptimized ASM (FPO → RBP frame) - ${deoptimizedAsm.length} lines`,
                icon: "deopt",
                columns: ["Instruction"],
                rows: deoptimizedAsm.map(line => [line]),
                isAsm: true,
                fpoDetected: true
            });
            console.log(`✅ Added FPO deoptimization table with ${deoptimizedAsm.length} entries`);
        }
    
        if (strings.length > 0) {
            this.result.tables.push({
                title: `📝 String Literals in .text (${strings.length})`,
                icon: "string",
                columns: ["RVA", "String"],
                rows: strings.map(s => [`0x${s.address.toString(16)}`, `"${s.value}"`])
            });
            console.log(`✅ Added strings table with ${strings.length} entries`);
        }
    
        if (cppCode.length > 0) {
            this.result.tables.push({
                title: `⚡ Decompiled C++ Code (${cppCode.length} lines)`,
                icon: "cpp",
                columns: ["Line"],
                rows: cppCode.map(line => [line]),
                isCpp: true,
                cppCode: cppCode
            });
            console.log(`✅ Added C++ decompilation table`);
        }
    
        clearTimeout(timeoutId);
        return { textBytes: textBytes, instructions: allInstructions, cppCode, strings, deoptimizedAsm, hasFpo };
    }

    filterDataSection(instructions, bytes, baseRVA) {
        if (!instructions || !Array.isArray(instructions) || instructions.length === 0) {
            console.log("filterDataSection: no valid instructions");
            return instructions || [];
        }
        
        let firstValidOffset = -1;
        let firstValidRVA = -1;
        
        for (let i = 0; i < instructions.length; i++) {
            const inst = instructions[i];
            
            // Пропускаємо undefined або null інструкції
            if (!inst || typeof inst !== 'object') {
                continue;
            }
            
            // Безпечне отримання полів з дефолтними значеннями
            const mnemonic = inst.mnemonic || '';
            const text = inst.text || '';
            const bytes_ = inst.bytes || '';
            
            const isRealCode = 
                // push rbp/ebp (пролог)
                (mnemonic === 'push' && (text.includes('rbp') || text.includes('ebp'))) ||
                // hotpatch пролог
                bytes_ === '8b ff' ||
                // call інструкції
                mnemonic === 'call' ||
                // ret інструкції
                mnemonic === 'ret' ||
                // jmp інструкції
                mnemonic === 'jmp' ||
                // mov з регістрами
                (mnemonic === 'mov' && (text.includes('eax') || text.includes('ebx') || 
                                        text.includes('ecx') || text.includes('edx') ||
                                        text.includes('esi') || text.includes('edi') ||
                                        text.includes('rax') || text.includes('rbx') ||
                                        text.includes('rcx') || text.includes('rdx') ||
                                        text.includes('rsi') || text.includes('rdi'))) ||
                // арифметика з регістрами
                (mnemonic === 'add' && (text.includes('eax') || text.includes('ebx') || 
                                        text.includes('rax') || text.includes('rbx'))) ||
                (mnemonic === 'sub' && (text.includes('eax') || text.includes('ebx') ||
                                        text.includes('rax') || text.includes('rbx'))) ||
                (mnemonic === 'xor' && (text.includes('eax') || text.includes('ebx') ||
                                        text.includes('rax') || text.includes('rbx'))) ||
                // loop
                mnemonic === 'loop' ||
                // test
                mnemonic === 'test' ||
                // cmp
                mnemonic === 'cmp' ||
                // умовні переходи (jz, jnz, jl, jg, etc)
                (mnemonic.startsWith('j') && mnemonic !== 'jmp');
            
            if (isRealCode && inst.offset !== undefined) {
                firstValidOffset = inst.offset;
                firstValidRVA = inst.rva;
                console.log(`Found first real code at offset 0x${firstValidOffset.toString(16)}, RVA 0x${firstValidRVA?.toString(16) || 'N/A'}: ${text}`);
                break;
            }
        }
        
        if (firstValidOffset !== -1) {
            const filteredInstructions = instructions.filter(inst => {
                if (!inst || inst.offset === undefined) return false;
                return inst.offset >= firstValidOffset;
            });
            console.log(`Filtered ${instructions.length - filteredInstructions.length} data instructions, kept ${filteredInstructions.length} real instructions`);
            return filteredInstructions;
        }
        
        console.log("No real code found, returning all instructions");
        return instructions;
    }
    
    extractStringsFromText(bytes, baseRVA) {
        console.time("extractStringsLoop");
        const strings = [];
        let i = 0;
        let iterations = 0;
        
        while (i < bytes.length) {
            iterations++;
            if (iterations % 10000 === 0) {
                console.log(`  extractStrings: iteration ${iterations}, i=${i}/${bytes.length}`);
            }
            
            while (i < bytes.length && bytes[i] === 0) i++;
            if (i >= bytes.length) break;
            
            let strBytes = [];
            let start = i;
            let isPrintable = true;
            
            while (i < bytes.length && bytes[i] !== 0) {
                const char = bytes[i];
                if (char < 0x20 || char > 0x7E) {
                    isPrintable = false;
                    break;
                }
                strBytes.push(char);
                i++;
            }
            
            if (isPrintable && strBytes.length >= 4) {
                const str = new TextDecoder('utf-8').decode(new Uint8Array(strBytes));
                if (!str.includes('\\') && !str.match(/^[0-9a-f]+$/i)) {
                    strings.push({
                        address: baseRVA + start,
                        value: str,
                        length: strBytes.length,
                        offset: start
                    });
                    if (strings.length % 50 === 0) {
                        console.log(`  Found ${strings.length} strings, last: "${str}"`);
                    }
                }
            }
            
            if (i < bytes.length && bytes[i] === 0) i++;
            
            if (i === start && i < bytes.length) i++;
        }
        
        console.timeEnd("extractStringsLoop");
        console.log(`  extractStrings finished: ${strings.length} strings, ${iterations} iterations`);
        
        strings.sort((a, b) => a.address - b.address);
        
        return strings;
    }

    scanRelocations() {
        const dataDir = this.getDataDirectory(5);
        if (dataDir.virtualAddress === 0 || dataDir.size === 0) {
            console.log("No relocation directory");
            return;
        }
        
        let offset = this.rvaToOffset(dataDir.virtualAddress);
        if (offset === -1) return;
        
        const relocations = [];
        let totalEntries = 0;
        const typeStats = {};
        
        while (offset < dataDir.virtualAddress + dataDir.size) {
            const pageRVA = this.view.getUint32(offset, true);
            const blockSize = this.view.getUint32(offset + 4, true);
            
            if (pageRVA === 0) break;
            
            const numEntries = (blockSize - 8) / 2;
            const entries = [];
            
            for (let i = 0; i < numEntries; i++) {
                const entryOffset = offset + 8 + i * 2;
                if (entryOffset + 1 >= this.bytes.length) break;
                
                const entry = this.view.getUint16(entryOffset, true);
                const type = entry >> 12;
                const offsetInPage = entry & 0xFFF;
                
                if (type !== 0) {
                    const typeName = this.getRelocationTypeName(type);
                    entries.push({
                        type: type,
                        offsetInPage: offsetInPage,
                        typeName: typeName,
                        rva: pageRVA + offsetInPage
                    });
                    typeStats[typeName] = (typeStats[typeName] || 0) + 1;
                }
            }
            
            if (entries.length > 0) {
                relocations.push({
                    pageRVA: pageRVA,
                    blockSize: blockSize,
                    entries: entries
                });
                totalEntries += entries.length;
            }
            
            offset += blockSize;
        }
        
        console.log(`📋 Found ${relocations.length} relocation blocks with ${totalEntries} entries`);
        
        this.report.relocations = relocations;
        
        if (relocations.length > 0) {
            this.result.tables.push({
                title: `🔄 Relocations (${totalEntries} entries in ${relocations.length} blocks)`,
                icon: "reloc",
                columns: ["Page RVA", "Entries Count", "Types"],
                rows: relocations.slice(0, 30).map(r => [
                    `0x${r.pageRVA.toString(16)}`,
                    r.entries.length,
                    [...new Set(r.entries.map(e => e.typeName))].join(", ")
                ])
            });
            
            if (relocations.length > 30) {
                this.result.tables[this.result.tables.length - 1].rows.push([
                    `... and ${relocations.length - 30} more pages`,
                    "",
                    ""
                ]);
            }
        }
        
        if (Object.keys(typeStats).length > 0) {
            this.result.tables.push({
                title: "📊 Relocation Type Statistics",
                icon: "stats",
                columns: ["Type", "Count", "Percentage"],
                rows: Object.entries(typeStats)
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, count]) => [
                        type, 
                        count, 
                        `${((count / totalEntries) * 100).toFixed(1)}%`
                    ])
            });
        }
    }
    
    getRelocationTypeName(type) {
        const names = {
            0: "ABSOLUTE (ignored)",
            1: "HIGH",
            2: "LOW",
            3: "HIGHLOW",
            4: "HIGHADJ",
            5: "MIPS_JMPADDR",
            6: "ARM_MOV32",
            7: "MIPS_JMPADDR16",
            8: "RESERVED",
            9: "DIR64",
            10: "MIPS_JMPADDR",
            11: "SECTION",
            12: "REL32",
            13: "REL32_1",
            14: "REL32_2",
            15: "REL32_3",
            16: "REL32_4",
            17: "REL32_5"
        };
        return names[type] || `Unknown(${type})`;
    }

    scanApiSetSchema() {
        const apisetSection = this.report.sections.find(s => s.name === '.apiset');
        if (!apisetSection) {
            console.log("No .apiset section found");
            return;
        }
    
        const offset = apisetSection.pointerToRawData;
        const size = apisetSection.sizeOfRawData;
    
        console.log(`📋 Parsing .apiset section: offset 0x${offset.toString(16)}, size ${size} bytes`);
        
        const strings = [];
        let currentOffset = offset;
        
        while (currentOffset + 1 < offset + size) {
            let str = "";
            let strOffset = currentOffset;
            while (strOffset + 1 < offset + size) {
                const charCode = this.view.getUint16(strOffset, true);
                if (charCode === 0) break;
                if (charCode < 0x20 || charCode > 0x7E) break;
                str += String.fromCharCode(charCode);
                strOffset += 2;
            }
            
            if (str.length > 2 && !str.includes(' ') && !str.includes('\t')) {
                strings.push(str);
            }
            currentOffset = strOffset + 2;
        }
        
        console.log(`Found ${strings.length} raw strings`);
        console.log("First 20 strings:", strings.slice(0, 20));
        
        const pendingApis = [];
        const entries = [];
        const seen = new Set();
        
        for (const str of strings) {
            const isApiSet = str.includes('-') && 
                             (str.includes('MS-Win') || 
                              str.includes('api-ms-win') ||
                              str.includes('ext-ms-win')) &&
                             !str.includes('.dll');
            
            const isDll = str.endsWith('.dll') && str.length > 6;
            
            if (isApiSet) {
                pendingApis.push(str);
            } 
            else if (isDll && pendingApis.length > 0) {
                for (const api of pendingApis) {
                    const key = `${api}|${str}`;
                    if (!seen.has(key)) {
                        seen.add(key);
                        entries.push({
                            name: api,
                            target: str,
                            targetList: str
                        });
                    }
                }
                pendingApis.length = 0;
            }
        }
        
        if (pendingApis.length > 0 && entries.length > 0) {
            const lastTarget = entries[entries.length - 1].target;
            for (const api of pendingApis) {
                const key = `${api}|${lastTarget}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    entries.push({
                        name: api,
                        target: lastTarget,
                        targetList: lastTarget
                    });
                }
            }
        }
        
        const groupedEntries = new Map();
        for (const e of entries) {
            if (!groupedEntries.has(e.name)) {
                groupedEntries.set(e.name, []);
            }
            groupedEntries.get(e.name).push(e.target);
        }
        
        const finalEntries = [];
        for (const [name, targets] of groupedEntries) {
            const uniqueTargets = [...new Set(targets)];
            finalEntries.push({
                name: name,
                targets: uniqueTargets,
                targetList: uniqueTargets.join(" → ")
            });
        }
        
        finalEntries.sort((a, b) => a.name.localeCompare(b.name));
        
        console.log(`✅ Found ${finalEntries.length} API Set mappings`);
    
        console.log("API Set mappings:");
        finalEntries.forEach(e => {
            console.log(`  ${e.name} → ${e.targets.join(", ")}`);
        });
        
        if (finalEntries.length > 0) {
            this.result.tables.push({
                title: `📋 API Set Schema (${finalEntries.length} entries)`,
                icon: "database",
                columns: ["API Set Name", "Target DLLs"],
                rows: finalEntries.map(e => [e.name, e.targetList])
            });
        }
    }
    
    scanUtf16Strings(offset, size) {
        console.log("Fallback: scanning UTF-16 strings...");
        const strings = [];
        const seen = new Set();
        let currentOffset = offset;
        
        while (currentOffset < offset + size) {
            // Шукаємо початок UTF-16 рядка (перший символ > 0x20)
            let foundStart = false;
            while (currentOffset + 1 < offset + size) {
                const charCode = this.view.getUint16(currentOffset, true);
                if (charCode >= 0x20 && charCode <= 0x7E && charCode !== 0) {
                    foundStart = true;
                    break;
                }
                currentOffset += 2;
            }
            if (!foundStart) break;
            
            let str = "";
            let strOffset = currentOffset;
            while (strOffset + 1 < offset + size) {
                const charCode = this.view.getUint16(strOffset, true);
                if (charCode === 0) break;
                if (charCode < 0x20 || charCode > 0x7E) {
                    // Не ASCII, пропускаємо
                    break;
                }
                str += String.fromCharCode(charCode);
                strOffset += 2;
            }
            
            if (str.length > 5 && (str.includes('MS-Win') || str.includes('api-ms-win') || 
                str.includes('kernel32') || str.includes('ntdll'))) {
                if (!seen.has(str)) {
                    seen.add(str);
                    strings.push(str);
                }
            }
            
            currentOffset = strOffset + 2;
        }
        
        if (strings.length > 0) {
            this.result.tables.push({
                title: `📋 API Set Strings (${strings.length} entries)`,
                icon: "database",
                columns: ["String"],
                rows: strings.map(s => [s])
            });
            console.log(`✅ Found ${strings.length} UTF-16 strings`);
        }
    }

    disassemble(bytes, baseRVA) {
        console.log(`  disassemble: starting with ${bytes.length} bytes at 0x${baseRVA.toString(16)}`);
        console.time("disassembleBytes");
        
        const instructions = [];
        let offset = 0;
        let lastLog = 0;
        
        const opcodeTable = {
            0x00: { mnem: "add", len: 2 }, 0x01: { mnem: "add", len: 2 }, 0x02: { mnem: "add", len: 2 }, 0x03: { mnem: "add", len: 2 },
            0x04: { mnem: "add", len: 2 }, 0x05: { mnem: "add", len: 5 },
            0x08: { mnem: "or", len: 2 }, 0x09: { mnem: "or", len: 2 }, 0x0A: { mnem: "or", len: 2 }, 0x0B: { mnem: "or", len: 2 },
            0x0C: { mnem: "or", len: 2 }, 0x0D: { mnem: "or", len: 5 },
            0x10: { mnem: "adc", len: 2 }, 0x11: { mnem: "adc", len: 2 }, 0x12: { mnem: "adc", len: 2 }, 0x13: { mnem: "adc", len: 2 },
            0x14: { mnem: "adc", len: 2 }, 0x15: { mnem: "adc", len: 5 },
            0x18: { mnem: "sbb", len: 2 }, 0x19: { mnem: "sbb", len: 2 }, 0x1A: { mnem: "sbb", len: 2 }, 0x1B: { mnem: "sbb", len: 2 },
            0x1C: { mnem: "sbb", len: 2 }, 0x1D: { mnem: "sbb", len: 5 },
            0x20: { mnem: "and", len: 2 }, 0x21: { mnem: "and", len: 2 }, 0x22: { mnem: "and", len: 2 }, 0x23: { mnem: "and", len: 2 },
            0x24: { mnem: "and", len: 2 }, 0x25: { mnem: "and", len: 5 },
            0x27: { mnem: "daa", len: 1 },
            0x28: { mnem: "sub", len: 2 }, 0x29: { mnem: "sub", len: 2 }, 0x2A: { mnem: "sub", len: 2 }, 0x2B: { mnem: "sub", len: 2 },
            0x2C: { mnem: "sub", len: 2 }, 0x2D: { mnem: "sub", len: 5 },
            0x2F: { mnem: "das", len: 1 },
            0x30: { mnem: "xor", len: 2 }, 0x31: { mnem: "xor", len: 2 }, 0x32: { mnem: "xor", len: 2 }, 0x33: { mnem: "xor", len: 2 },
            0x34: { mnem: "xor", len: 2 }, 0x35: { mnem: "xor", len: 5 },
            0x37: { mnem: "aaa", len: 1 },
            0x38: { mnem: "cmp", len: 2 }, 0x39: { mnem: "cmp", len: 2 }, 0x3A: { mnem: "cmp", len: 2 }, 0x3B: { mnem: "cmp", len: 2 },
            0x3C: { mnem: "cmp", len: 2 }, 0x3D: { mnem: "cmp", len: 5 },
            0x3F: { mnem: "aas", len: 1 },
            0x40: { mnem: "inc rax", len: 1 }, 0x41: { mnem: "inc rcx", len: 1 }, 0x42: { mnem: "inc rdx", len: 1 },
            0x43: { mnem: "inc rbx", len: 1 }, 0x44: { mnem: "inc rsp", len: 1 }, 0x45: { mnem: "inc rbp", len: 1 },
            0x46: { mnem: "inc rsi", len: 1 }, 0x47: { mnem: "inc rdi", len: 1 },
            0x48: { mnem: "dec rax", len: 1 }, 0x49: { mnem: "dec rcx", len: 1 }, 0x4A: { mnem: "dec rdx", len: 1 },
            0x4B: { mnem: "dec rbx", len: 1 }, 0x4C: { mnem: "dec rsp", len: 1 }, 0x4D: { mnem: "dec rbp", len: 1 },
            0x4E: { mnem: "dec rsi", len: 1 }, 0x4F: { mnem: "dec rdi", len: 1 },
            0x50: { mnem: "push rax", len: 1 }, 0x51: { mnem: "push rcx", len: 1 }, 0x52: { mnem: "push rdx", len: 1 },
            0x53: { mnem: "push rbx", len: 1 }, 0x54: { mnem: "push rsp", len: 1 }, 0x55: { mnem: "push rbp", len: 1 },
            0x56: { mnem: "push rsi", len: 1 }, 0x57: { mnem: "push rdi", len: 1 },
            0x58: { mnem: "pop rax", len: 1 }, 0x59: { mnem: "pop rcx", len: 1 }, 0x5A: { mnem: "pop rdx", len: 1 },
            0x5B: { mnem: "pop rbx", len: 1 }, 0x5C: { mnem: "pop rsp", len: 1 }, 0x5D: { mnem: "pop rbp", len: 1 },
            0x5E: { mnem: "pop rsi", len: 1 }, 0x5F: { mnem: "pop rdi", len: 1 },
            0x06: { mnem: "push es", len: 1 }, 0x07: { mnem: "pop es", len: 1 },
            0x0E: { mnem: "push cs", len: 1 }, 0x16: { mnem: "push ss", len: 1 }, 0x17: { mnem: "pop ss", len: 1 },
            0x1E: { mnem: "push ds", len: 1 }, 0x1F: { mnem: "pop ds", len: 1 },
            0x88: { mnem: "mov", len: 2 }, 0x89: { mnem: "mov", len: 2 }, 0x8A: { mnem: "mov", len: 2 }, 0x8B: { mnem: "mov", len: 2 },
            0x8C: { mnem: "mov", len: 2 }, 0x8D: { mnem: "lea", len: 2 }, 0x8E: { mnem: "mov", len: 2 },
            0x8F: { mnem: "pop", len: 2 },
            0xA0: { mnem: "mov", len: 5 }, 0xA1: { mnem: "mov", len: 5 }, 0xA2: { mnem: "mov", len: 5 }, 0xA3: { mnem: "mov", len: 5 },
            0xA4: { mnem: "movsb", len: 1 }, 0xA5: { mnem: "movsw", len: 1 },
            0xA6: { mnem: "cmpsb", len: 1 }, 0xA7: { mnem: "cmpsw", len: 1 },
            0xAA: { mnem: "stosb", len: 1 }, 0xAB: { mnem: "stosw", len: 1 },
            0xAC: { mnem: "lodsb", len: 1 }, 0xAD: { mnem: "lodsw", len: 1 },
            0xAE: { mnem: "scasb", len: 1 }, 0xAF: { mnem: "scasw", len: 1 },
            0x9A: { mnem: "call far", len: 5 },
            0xC2: { mnem: "ret", len: 3 }, 0xC3: { mnem: "ret", len: 1 },
            0xCA: { mnem: "retf", len: 3 }, 0xCB: { mnem: "retf", len: 1 },
            0xCC: { mnem: "int3", len: 1 }, 0xCD: { mnem: "int", len: 2 },
            0xCE: { mnem: "into", len: 1 }, 0xCF: { mnem: "iret", len: 1 },
            0xE0: { mnem: "loopne", len: 2 }, 0xE1: { mnem: "loope", len: 2 }, 0xE2: { mnem: "loop", len: 2 },
            0xE3: { mnem: "jcxz", len: 2 }, 0xE8: { mnem: "call", len: 5 }, 0xE9: { mnem: "jmp", len: 5 },
            0xEA: { mnem: "jmp far", len: 5 }, 0xEB: { mnem: "jmp", len: 2 },
            0x70: { mnem: "jo", len: 2 }, 0x71: { mnem: "jno", len: 2 }, 0x72: { mnem: "jb", len: 2 },
            0x73: { mnem: "jnb", len: 2 }, 0x74: { mnem: "jz", len: 2 }, 0x75: { mnem: "jnz", len: 2 },
            0x76: { mnem: "jbe", len: 2 }, 0x77: { mnem: "jnbe", len: 2 }, 0x78: { mnem: "js", len: 2 },
            0x79: { mnem: "jns", len: 2 }, 0x7A: { mnem: "jp", len: 2 }, 0x7B: { mnem: "jnp", len: 2 },
            0x7C: { mnem: "jl", len: 2 }, 0x7D: { mnem: "jnl", len: 2 }, 0x7E: { mnem: "jle", len: 2 },
            0x7F: { mnem: "jnle", len: 2 },
            0x90: { mnem: "nop", len: 1 }, 0x91: { mnem: "xchg rcx,rax", len: 1 }, 0x92: { mnem: "xchg rdx,rax", len: 1 },
            0x93: { mnem: "xchg rbx,rax", len: 1 }, 0x94: { mnem: "xchg rsp,rax", len: 1 }, 0x95: { mnem: "xchg rbp,rax", len: 1 },
            0x96: { mnem: "xchg rsi,rax", len: 1 }, 0x97: { mnem: "xchg rdi,rax", len: 1 },
            0x98: { mnem: "cbw", len: 1 }, 0x99: { mnem: "cwd", len: 1 },
            0x9B: { mnem: "fwait", len: 1 }, 0x9C: { mnem: "pushf", len: 1 }, 0x9D: { mnem: "popf", len: 1 },
            0x9E: { mnem: "sahf", len: 1 }, 0x9F: { mnem: "lahf", len: 1 },
            0xD4: { mnem: "aam", len: 2 }, 0xD5: { mnem: "aad", len: 2 },
            0xD6: { mnem: "salc", len: 1 }, 0xD7: { mnem: "xlat", len: 1 },
            0x80: { mnem: "add", len: 2 }, 0x81: { mnem: "add", len: 6 }, 0x82: { mnem: "add", len: 2 }, 0x83: { mnem: "add", len: 3 },
            0x84: { mnem: "test", len: 2 }, 0x85: { mnem: "test", len: 2 },
            0x86: { mnem: "xchg", len: 2 }, 0x87: { mnem: "xchg", len: 2 },
            0xA8: { mnem: "test", len: 2 }, 0xA9: { mnem: "test", len: 5 },
            0xC0: { mnem: "rol", len: 3 }, 0xC1: { mnem: "rol", len: 3 },
            0xC6: { mnem: "mov", len: 2 }, 0xC7: { mnem: "mov", len: 6 },
            0xFE: { mnem: "inc", len: 2 }, 0xFF: { mnem: "inc", len: 2 },
            0xF6: { mnem: "test", len: 2 }, 0xF7: { mnem: "test", len: 2 },
            0x0F: { mnem: "nop", len: 2, isTwoByte: true }
        };
        
        const opcodeTableTwoByte = {
            0x00: { mnem: "sldt", len: 2 }, 0x01: { mnem: "sgdt", len: 2 },
            0x02: { mnem: "lar", len: 2 }, 0x03: { mnem: "lsl", len: 2 },
            0x04: { mnem: "loadall", len: 1 }, 0x05: { mnem: "syscall", len: 1 },
            0x06: { mnem: "clts", len: 1 }, 0x07: { mnem: "sysret", len: 1 },
            0x08: { mnem: "invd", len: 1 }, 0x09: { mnem: "wbinvd", len: 1 },
            0x0B: { mnem: "ud2", len: 1 }, 0x0D: { mnem: "prefetch", len: 2 },
            0x1F: { mnem: "nop", len: 2 }, 0x31: { mnem: "rdtsc", len: 1 },
            0x34: { mnem: "sysenter", len: 1 }, 0x35: { mnem: "sysexit", len: 1 },
            0xA2: { mnem: "cpuid", len: 1 }, 0xAF: { mnem: "imul", len: 2 },
            0xB0: { mnem: "cmpxchg", len: 2 }, 0xB1: { mnem: "cmpxchg", len: 2 },
            0xB6: { mnem: "movzx", len: 2 }, 0xB7: { mnem: "movzx", len: 2 },
            0xBE: { mnem: "movsx", len: 2 }, 0xBF: { mnem: "movsx", len: 2 },
            0xC7: { mnem: "cmpxchg8b", len: 2 }, 0xC8: { mnem: "bswap", len: 1 }
        };
        
        while (offset < bytes.length) {
            const opcode = bytes[offset];
            const rva = baseRVA + offset;
            let instLength = 1;
            let instText = "???";
            let instBytes = [];
            
            for (let i = 0; i < Math.min(15, bytes.length - offset); i++) {
                instBytes.push(bytes[offset + i].toString(16).padStart(2, '0'));
            }
            
            // REX prefix (x64)
            const isREX = (opcode & 0xF0) === 0x40 && opcode >= 0x40 && opcode <= 0x4F;
            let rexW = false;
            let rexR = false;
            let rexX = false;
            let rexB = false;
            
            if (isREX) {
                rexW = (opcode & 0x08) !== 0;
                rexR = (opcode & 0x04) !== 0;
                rexX = (opcode & 0x02) !== 0;
                rexB = (opcode & 0x01) !== 0;
                instLength = 1;
                
                const nextOp = bytes[offset + 1];
                const entry = opcodeTable[nextOp];
                
                if (entry) {
                    instLength += entry.len;
                    let mnem = entry.mnem;
                    if (rexW && (mnem === "mov" || mnem === "add" || mnem === "sub" || mnem === "imul")) {
                        mnem = mnem + "q";
                    }
                    instText = mnem;
                } else if (nextOp === 0x0F) {
                    const thirdOp = bytes[offset + 2];
                    const twoByteEntry = opcodeTableTwoByte[thirdOp];
                    if (twoByteEntry) {
                        instLength += 1 + twoByteEntry.len;
                        instText = twoByteEntry.mnem;
                        if (rexW && (instText === "mov" || instText === "cmpxchg")) {
                            instText = instText + "q";
                        }
                    } else {
                        instText = `rex.${opcode.toString(16)} ${nextOp.toString(16)} ${thirdOp ? bytes[offset + 2].toString(16) : '?'}`;
                        instLength = 3;
                    }
                } else {
                    instText = `rex.${opcode.toString(16)} ${nextOp ? bytes[offset + 1].toString(16) : '?'}`;
                    instLength = 2;
                }
            } else if (opcode === 0x0F) {
                const second = bytes[offset + 1];
                const entry = opcodeTableTwoByte[second];
                
                if (entry) {
                    instLength = entry.len + 1;
                    instText = entry.mnem;
                    
                    if (entry.len > 1 && offset + 2 < bytes.length) {
                        const modrm = bytes[offset + 2];
                        const reg = (modrm >> 3) & 7;
                        const rm = modrm & 7;
                        const regNames = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
                        
                        if (entry.mnem === "movzx" || entry.mnem === "movsx") {
                            instText = `${entry.mnem} ${regNames[reg]}, [${regNames[rm]}]`;
                        } else if (entry.mnem === "imul") {
                            instText = `imul ${regNames[reg]}, [${regNames[rm]}]`;
                        }
                    }
                } else if (second === 0x1F && bytes[offset + 2] === 0x00) {
                    instLength = 3;
                    instText = "nop";
                } else {
                    instLength = 2;
                    instText = `0f ${second.toString(16)}`;
                }
            } else {
                const entry = opcodeTable[opcode];
                
                if (entry) {
                    instLength = entry.len;
                    instText = entry.mnem;
                    
                    if ((instText === "mov" || instText === "add" || instText === "sub" || 
                         instText === "cmp" || instText === "and" || instText === "or" || 
                         instText === "xor" || instText === "test") && instLength === 2) {
                        const modrm = bytes[offset + 1];
                        const reg = (modrm >> 3) & 7;
                        const rm = modrm & 7;
                        const regNames = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
                        
                        const size = (opcode >= 0x80 && opcode <= 0x83) ? "byte" : 
                                     (opcode >= 0x88 && opcode <= 0x8F) ? "word" : "dword";
                        
                        instText = `${instText} ${regNames[reg]}, [${regNames[rm]}]`;
                    } else if (instText === "mov" && instLength === 5 && (opcode === 0xA0 || opcode === 0xA1)) {
                        const disp = bytes[offset + 1] | (bytes[offset + 2] << 8) | 
                                     (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24);
                        instText = `mov rax, [0x${disp.toString(16)}]`;
                    } else if (instText === "call" && instLength === 5) {
                        const disp = bytes[offset + 1] | (bytes[offset + 2] << 8) | 
                                     (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24);
                        instText = `call 0x${(rva + 5 + disp).toString(16)}`;
                    } else if (instText === "jmp" && instLength === 5) {
                        const disp = bytes[offset + 1] | (bytes[offset + 2] << 8) | 
                                     (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24);
                        instText = `jmp 0x${(rva + 5 + disp).toString(16)}`;
                    } else if (instText === "jmp" && instLength === 2) {
                        const disp = bytes[offset + 1];
                        instText = `jmp 0x${(rva + 2 + (disp > 127 ? disp - 256 : disp)).toString(16)}`;
                    } else if ((instText === "jz" || instText === "jnz" || instText === "jl" || 
                                instText === "jnl" || instText === "jo" || instText === "jno" ||
                                instText === "js" || instText === "jns" || instText === "jp" || 
                                instText === "jnp" || instText === "jb" || instText === "jnb" ||
                                instText === "jbe" || instText === "jnbe" || instText === "jle" || 
                                instText === "jnle" || instText === "loop" || instText === "loope" || 
                                instText === "loopne" || instText === "jcxz") && instLength === 2) {
                        const disp = bytes[offset + 1];
                        instText = `${instText} 0x${(rva + 2 + (disp > 127 ? disp - 256 : disp)).toString(16)}`;
                    }
                } else {
                    instText = `db ${opcode.toString(16)}`;
                }
            }
            
            instructions.push({
                rva: rva,
                offset: offset,
                bytes: instBytes.slice(0, instLength).join(' '),
                text: instText,
                length: instLength
            });
            
            offset += instLength;
        }
        console.timeEnd("disassembleBytes");
        console.log(`  disassemble finished: ${instructions.length} instructions`);
        return instructions;
    }    
    
    scanResources() {
        const dataDir = this.getDataDirectory(2);
        if (dataDir.virtualAddress === 0) return;
        
        const offset = this.rvaToOffset(dataDir.virtualAddress);
        if (offset !== -1) {
            this.parseResourceDirectory(offset, []);
        }
        
        for (const res of this.report.resources.other) {
            if (res.type === 16) {
                this.report.resources.version = { type: "VERSIONINFO", size: res.size };
                break;
            }
        }
    }
    
    parseResourceDirectory(offset, path) {
        const numberOfNamedEntries = this.view.getUint16(offset + 12, true);
        const numberOfIdEntries = this.view.getUint16(offset + 14, true);
        const totalEntries = numberOfNamedEntries + numberOfIdEntries;
        
        for (let i = 0; i < totalEntries; i++) {
            const entryOffset = offset + 16 + i * 8;
            const nameOrId = this.view.getUint32(entryOffset, true);
            const dataOrSubdir = this.view.getUint32(entryOffset + 4, true);
            
            const isDirectory = (dataOrSubdir & 0x80000000) !== 0;
            const identifier = (nameOrId & 0x80000000) !== 0 ?
                this.readResourceName(nameOrId & 0x7FFFFFFF) : nameOrId;
            
            const newPath = [...path, identifier];
            
            if (isDirectory) {
                const subdirOffset = this.rvaToOffset(dataOrSubdir & 0x7FFFFFFF);
                if (subdirOffset !== -1) {
                    this.parseResourceDirectory(subdirOffset, newPath);
                }
            } else {
                const dataOffset = this.rvaToOffset(dataOrSubdir);
                const dataSize = this.view.getUint32(dataOffset, true);
                
                const resource = { type: path[0], name: path[1], language: path[2], size: dataSize };
                const typeId = typeof path[0] === 'number' ? path[0] : 0;
                
                switch (typeId) {
                    case 1: this.report.resources.icons.push(resource); break;
                    case 6: this.report.resources.strings.push(resource); break;
                    default: this.report.resources.other.push(resource);
                }
            }
        }
    }
    
    readResourceName(nameRVA) {
        const offset = this.rvaToOffset(nameRVA);
        if (offset === -1) return "?";
        const length = this.view.getUint16(offset, true);
        const chars = [];
        for (let i = 0; i < length; i++) {
            chars.push(String.fromCharCode(this.view.getUint16(offset + 2 + i * 2, true)));
        }
        return chars.join('');
    }
    
    scanTLS() {
        const dataDir = this.getDataDirectory(9);
        if (dataDir.virtualAddress === 0) return;
        const offset = this.rvaToOffset(dataDir.virtualAddress);
        if (offset === -1) return;
        let addrOfCallbacksVA;
        
        if (this.is64bit) {
            addrOfCallbacksVA = this.view.getBigUint64(offset + 24, true);
            this.report.tls = {
                startAddressOfRawData: `0x${this.view.getBigUint64(offset, true).toString(16)}`,
                endAddressOfRawData: `0x${this.view.getBigUint64(offset + 8, true).toString(16)}`,
                addressOfIndex: `0x${this.view.getBigUint64(offset + 16, true).toString(16)}`,
                addressOfCallbacks: `0x${addrOfCallbacksVA.toString(16)}`
            };
        } else {
            addrOfCallbacksVA = BigInt(this.view.getUint32(offset + 12, true));
            this.report.tls = {
                startAddressOfRawData: `0x${this.view.getUint32(offset, true).toString(16)}`,
                endAddressOfRawData: `0x${this.view.getUint32(offset + 4, true).toString(16)}`,
                addressOfIndex: `0x${this.view.getUint32(offset + 8, true).toString(16)}`,
                addressOfCallbacks: `0x${addrOfCallbacksVA.toString(16)}`
            };
        }
    
        const callbacksArrayOffset = this.rvaToOffset(
            Number(addrOfCallbacksVA - this.imageBase)
        );
        
        if (callbacksArrayOffset !== -1) {
            let firstCallbackVA = this.is64bit 
                ? this.view.getBigUint64(callbacksArrayOffset, true)
                : BigInt(this.view.getUint32(callbacksArrayOffset, true));
            
            if (firstCallbackVA !== 0n) {
                this.tlsentptaddr = this.rvaToOffset(
                    Number(firstCallbackVA - this.imageBase)
                );
            }
        }
    }
    
    scanExceptions() {
        console.log("🔍 Scanning exception handlers...");
        
        const pdataSection = this.report.sections.find(s => s.name === '.pdata');
        console.log("pdata section found:", pdataSection ? "yes" : "no");
        
        if (!pdataSection) {
            console.log("No .pdata section, skipping exception handlers");
            return;
        }
        
        console.log(`.pdata section - VA: 0x${pdataSection.virtualAddress.toString(16)}, Size: ${pdataSection.virtualSize} bytes`);
        
        const offset = pdataSection.pointerToRawData;
        if (offset === 0 || offset + pdataSection.virtualSize > this.bytes.length) {
            console.log("Invalid .pdata section offset");
            return;
        }
        
        const entrySize = this.is64bit ? 12 : 8;
        const numberOfEntries = Math.floor(pdataSection.virtualSize / entrySize);
        console.log(`📋 Parsing ${numberOfEntries} exception entries from .pdata`);
        
        for (let i = 0; i < numberOfEntries; i++) {
            const entryOffset = offset + i * entrySize;
            
            if (entryOffset + entrySize > this.bytes.length) break;
            
            const beginRVA = this.view.getUint32(entryOffset, true);
            const endRVA = this.view.getUint32(entryOffset + 4, true);
            const unwindRVA = this.is64bit ? this.view.getUint32(entryOffset + 8, true) : 0;
            
            const exception = {
                index: i,
                beginAddress: `0x${beginRVA.toString(16)}`,
                endAddress: `0x${endRVA.toString(16)}`,
                unwindInfoAddress: unwindRVA ? `0x${unwindRVA.toString(16)}` : null,
                functionSize: endRVA - beginRVA,
                unwindInfo: null
            };
            
            if (this.is64bit && unwindRVA !== 0) {
                const unwindOffset = this.rvaToOffset(unwindRVA);
                if (unwindOffset !== -1 && unwindOffset + 4 < this.bytes.length) {
                    const version = this.bytes[unwindOffset] & 0x07;
                    const flags = (this.bytes[unwindOffset] >> 3) & 0x1F;
                    const sizeOfProlog = this.bytes[unwindOffset + 1];
                    const countOfCodes = this.bytes[unwindOffset + 2];
                    const frameRegister = this.bytes[unwindOffset + 3] & 0x0F;
                    const frameOffset = (this.bytes[unwindOffset + 3] >> 4) & 0x0F;
                    
                    const unwindInfo = {
                        version,
                        flags,
                        sizeOfProlog,
                        countOfCodes,
                        frameRegister,
                        frameOffset,
                        codes: []
                    };
                    
                    const codesOffset = unwindOffset + 4;
                    for (let j = 0; j < countOfCodes; j++) {
                        const codeOffset = codesOffset + j * 2;
                        if (codeOffset + 1 < this.bytes.length) {
                            const code = this.view.getUint16(codeOffset, true);
                            unwindInfo.codes.push({
                                offset: (code >> 8) & 0xFF,
                                opcode: code & 0xFF
                            });
                        }
                    }
                    
                    exception.unwindInfo = unwindInfo;
                }
            }
            
            this.report.exceptions.push(exception);
        }
        
        console.log(`✅ Parsed ${this.report.exceptions.length} exception handlers`);
        
        if (this.report.exceptions.length > 0) {
            this.result.tables.push({
                title: `⚠️ Exception Handlers (${this.report.exceptions.length})`,
                icon: "exception",
                columns: ["Index", "Begin RVA", "End RVA", "Size", "Unwind RVA", "Prolog Size", "Frame"],
                rows: this.report.exceptions.slice(0, 100).map(e => [
                    e.index,
                    e.beginAddress,
                    e.endAddress,
                    `0x${e.functionSize.toString(16)}`,
                    e.unwindInfoAddress || "N/A",
                    e.unwindInfo ? e.unwindInfo.sizeOfProlog : "N/A",
                    e.unwindInfo ? `R${e.unwindInfo.frameRegister}+${e.unwindInfo.frameOffset * 16}` : "N/A"
                ])
            });
        }
    }
    
    scanDebug() {
        const dataDir = this.getDataDirectory(6);
        if (dataDir.virtualAddress === 0) return;
        
        let offset = this.rvaToOffset(dataDir.virtualAddress);
        if (offset === -1) return;
        
        const numEntries = Math.floor(dataDir.size / 28);
        
        for (let i = 0; i < numEntries; i++) {
            const entryOffset = offset + i * 28;
            const type = this.view.getUint32(entryOffset + 12, true);
            
            if (type === 2) {
                const pointerToRawData = this.view.getUint32(entryOffset + 24, true);
                if (pointerToRawData !== 0) {
                    const pdbOffset = this.rvaToOffset(pointerToRawData);
                    if (pdbOffset !== -1) {
                        const signature = this.readString(pdbOffset, 4);
                        if (signature === "RSDS") {
                            this.report.debug = [{
                                type: "PDB",
                                pdbName: this.readString(pdbOffset + 24, 256),
                                age: this.view.getUint32(pdbOffset + 4, true),
                                guid: this.readGuid(pdbOffset + 8)
                            }];
                            break;
                        }
                    }
                }
            }
        }
    }
    
    readGuid(offset) {
        const data1 = this.view.getUint32(offset, true);
        const data2 = this.view.getUint16(offset + 4, true);
        const data3 = this.view.getUint16(offset + 6, true);
        const data4 = [];
        for (let i = 0; i < 8; i++) {
            data4.push(this.view.getUint8(offset + 8 + i).toString(16).padStart(2, '0'));
        }
        return `${data1.toString(16).padStart(8, '0')}-${data2.toString(16).padStart(4, '0')}-${data3.toString(16).padStart(4, '0')}-${data4.slice(0,2).join('')}-${data4.slice(2).join('')}`;
    }
    
    scanSecurityCookie() {
        const pattern = [0x5F, 0x5F, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x5F, 0x63, 0x6F, 0x6F, 0x6B, 0x69, 0x65];
        for (let i = 0; i < this.bytes.length - pattern.length; i++) {
            let match = true;
            for (let j = 0; j < pattern.length; j++) {
                if (this.bytes[i + j] !== pattern[j]) { match = false; break; }
            }
            if (match) {
                this.report.securityCookie = { found: true, offset: i };
                break;
            }
        }
    }
    
    scanControlFlowGuard() {
        const dataDir = this.getDataDirectory(20);
        if (dataDir.virtualAddress !== 0) {
            const offset = this.rvaToOffset(dataDir.virtualAddress);
            if (offset !== -1) {
                const guardCFCheckFunctionPointer = this.is64bit ?
                    this.view.getBigUint64(offset + 104, true) :
                    this.view.getUint32(offset + 64, true);
                
                if (guardCFCheckFunctionPointer !== 0n && guardCFCheckFunctionPointer !== 0) {
                    this.report.controlFlowGuard = { enabled: true };
                }
            }
        }
    }
    
    getDataDirectory(index) {
        const peOffset = this.report.dosHeader.e_lfanew;
        const magic = this.view.getUint16(peOffset + 24, true);
        const isPE32Plus = magic === 0x20B;
        const dataDirOffset = peOffset + (isPE32Plus ? 144 : 128);
        
        if (dataDirOffset + (index * 8) + 8 > this.bytes.length) {
            console.warn(`getDataDirectory: index ${index} out of bounds`);
            return { virtualAddress: 0, size: 0 };
        }
        
        return {
            virtualAddress: this.view.getUint32(dataDirOffset + index * 8, true),
            size: this.view.getUint32(dataDirOffset + index * 8 + 4, true)
        };
    }
    
    rvaToOffset(rva) {
        if (rva === 0) return -1;
        
        const rvaNum = typeof rva === 'bigint' ? Number(rva) : rva;
        
        for (const section of this.report.sections) {
            const sectionStart = section.virtualAddress;
            const sectionEnd = section.virtualAddress + section.virtualSize;
            
            if (rvaNum >= sectionStart && rvaNum < sectionEnd) {
                if (section.pointerToRawData === 0) {
                    console.log(`Section ${section.name} has no raw data (pointerToRawData=0), RVA 0x${rvaNum.toString(16)} points to uninitialized data`);
                    return -1;
                }
                
                const offset = section.pointerToRawData + (rvaNum - sectionStart);
                
                if (offset >= 0 && offset < this.bytes.length) {
                    return offset;
                } else {
                    console.warn(`rvaToOffset: offset ${offset} out of bounds (file size: ${this.bytes.length}) for section ${section.name}`);
                    return -1;
                }
            }
        }
        
        console.warn(`rvaToOffset: RVA 0x${rvaNum.toString(16)} not found in any section`);
        return -1;
    }

    readAsciiString(offset, maxLength) {
        let str = '';
        for (let i = 0; i < maxLength && offset + i < this.bytes.length; i++) {
            const char = this.bytes[offset + i];
            if (char === 0) break;
            str += String.fromCharCode(char);
        }
        return str;
    }
    
    readString(offset, maxLength) {
        const bytes = [];
        for (let i = 0; i < maxLength && offset + i < this.bytes.length; i += 2) {
            const charCode = this.view.getUint16(offset + i, true);
            if (charCode === 0) break;
            bytes.push(String.fromCharCode(charCode));
        }
        return bytes.join('');
    }
    
    readAsciiString(offset, maxLength) {
        let str = '';
        for (let i = 0; i < maxLength && offset + i < this.bytes.length; i++) {
            const char = this.bytes[offset + i];
            if (char === 0) break;
            str += String.fromCharCode(char);
        }
        return str;
    }
    
    getMachineName(machine) {
        const names = { 0x14C: "x86", 0x8664: "x64", 0x200: "IA64", 0xAA64: "ARM64", 0x1C0: "ARM" };
        return names[machine] || `Unknown (0x${machine.toString(16)})`;
    }
    
    getSubsystemName(subsystem) {
        const names = { 0: "Unknown", 1: "Native", 2: "Windows GUI", 3: "Windows CUI", 5: "OS/2 CUI", 7: "POSIX CUI" };
        return names[subsystem] || `Unknown (${subsystem})`;
    }
    
    buildSummary() {
        return {
            fileName: this.report.fileInfo.name || "Unknown",
            size: this.report.fileInfo.size,
            architecture: this.report.ntHeaders.machine,
            exports: this.report.exports.functions.length,
            forwarders: this.report.exports.forwarders.length,
            imports: this.report.imports.length,
            sections: this.report.sections.length,
            hasPDB: !!this.report.debug,
            hasTLS: !!this.report.tls,
            hasExceptions: this.report.exceptions.length > 0
        };
    }
}

class CppDecompiler {
    constructor(binaryBuffer, instructions, imports = [], strings = []) {
        console.log("=== CppDecompiler Constructor ===");
        console.log("Instructions count:", instructions?.length || 0);
        console.log("Imports count:", imports?.length || 0);
        console.log("Strings count:", strings?.length || 0);
        
        this.buffer = binaryBuffer;
        
        let rawInsts = [];
        if (instructions && Array.isArray(instructions)) {
            rawInsts = instructions
                .filter(inst => inst && typeof inst === 'object')
                .map(inst => {
                    let rvaNum = 0;
                    if (inst.rva !== undefined && inst.rva !== null) {
                        rvaNum = typeof inst.rva === 'bigint' ? Number(inst.rva) : Number(inst.rva);
                        if (isNaN(rvaNum)) rvaNum = 0;
                    }
                    
                    let mnemonic = '';
                    const text = inst.text || '';
                    const firstSpace = text.indexOf(' ');
                    if (firstSpace > 0) {
                        mnemonic = text.substring(0, firstSpace);
                    } else {
                        mnemonic = text;
                    }
                    
                    return {
                        ...inst,
                        rva: rvaNum,
                        mnemonic: mnemonic,
                        text: text,
                        bytes: inst.bytes || '',
                        offset: inst.offset || 0,
                        length: inst.length || 1
                    };
                });
        }
    
        this.instructions = rawInsts.filter(inst => inst && inst.mnemonic && inst.mnemonic !== '');
        
        console.log(`Filtered to ${this.instructions.length} valid instructions`);
        
        if (this.instructions.length > 0) {
            console.log("First 10 instructions:");
            this.instructions.slice(0, 10).forEach((inst, idx) => {
                console.log(`  ${idx}: 0x${inst.rva?.toString(16)} | ${inst.mnemonic} | ${inst.text}`);
            });
        } else {
            console.warn("No valid instructions! Raw instructions sample:");
            if (instructions && instructions.length > 0) {
                instructions.slice(0, 5).forEach((inst, idx) => {
                    console.log(`  ${idx}:`, inst);
                });
            }
        }
        
        this.imports = Array.isArray(imports) ? imports : [];
        
        this.strings = [];
        if (strings && Array.isArray(strings)) {
            this.strings = strings
                .filter(str => str && typeof str === 'object')
                .map(str => {
                    let addrNum = 0;
                    if (str.address !== undefined && str.address !== null) {
                        addrNum = typeof str.address === 'bigint' ? Number(str.address) : Number(str.address);
                        if (isNaN(addrNum)) addrNum = 0;
                    }
                    
                    return {
                        ...str,
                        address: addrNum,
                        value: str.value || '',
                        length: str.length || 0,
                        offset: str.offset || 0
                    };
                });
        }
        
        console.log(`Processed ${this.strings.length} strings`);
        
        this.cppLines = [];
        this.functions = [];
        this.globalVars = new Map();
        
        if (typeof GUECMan !== 'undefined') {
            GUECMan.ConnectToClass(this);
        }
    }

    async decompile() {
        console.log("=== CppDecompiler.decompile() START ===");
        console.log(`Total instructions: ${this.instructions.length}`);
        
        this.cppLines = [];
        this.cppLines.push('// Generated by RSDEFD C++ Decompiler v2.0');
        this.cppLines.push('// Decompiled C++ based by JS CPU calculations');
        this.cppLines.push('');
        
        const dlls = this.extractDllNames();
        console.log("DLLs found:", dlls);
        
        const includeMap = {
            "ole32.dll": "#include <ole2.h>        // OLE/COM",
            "oleaut32.dll": "#include <oaidl.h>     // OLE Automation",
            "setupapi.dll": "#include <setupapi.h>  // Device Installation",
            "shell32.dll": "#include <shellapi.h>   // Shell API",
            "user32.dll": "#include <windows.h>     // User interface API",
            "gdi32.dll": "#include <windows.h>      // GDI graphics API",
            "kernel32.dll": "#include <windows.h>   // Core Win32 API",
            "ntdll.dll": "#include <winternl.h>     // Native API (undocumented)",
            "advapi32.dll": "#include <windows.h>   // Registry, security API",
            "msvcrt.dll": "#include <cstdlib>\n#include <cstdio> // C Runtime",
            "comctl32.dll": "#include <commctrl.h>  // Common Controls",
            "wininet.dll": "#include <wininet.h>    // Internet API",
            "ws2_32.dll": "#include <winsock2.h>\n#include <ws2tcpip.h> // Networking",
            "crypt32.dll": "#include <wincrypt.h>   // Crypto API",
            "rpcrt4.dll": "#include <rpc.h>         // RPC API",
            "urlmon.dll": "#include <urlmon.h>      // URL monikers / download",
            "imm32.dll": "#include <imm.h>          // Input Method Manager",
            "shlwapi.dll": "#include <shlwapi.h>    // Shell light-weight API",
            "mpr.dll": "#include <mpr.h>            // Network connections",
            "dbghelp.dll": "#include <dbghelp.h>    // Debug help functions",
            "oleacc.dll": "#include <oleacc.h>      // Accessibility",
            "dwmapi.dll": "#include <dwmapi.h>      // Desktop Window Manager"
        };
            
        for (const dll of dlls) {
            const key = dll.toLowerCase();
            if (includeMap[key]) {
                this.cppLines.push(includeMap[key]);
                console.log(`Added include for: ${key}`);
            }
        }
        this.cppLines.push('');

        if (this.strings.length > 0) {
            this.cppLines.push('// Strings found in .text:');
            for (const str of this.strings.slice(0, 20)) {
                this.cppLines.push(`//   0x${str.address.toString(16)}: "${str.value}"`);
            }
            this.cppLines.push('');
            console.log(`Added ${Math.min(20, this.strings.length)} strings to comment`);
        }

        console.log("Building function map...");
        this.buildFunctionMap();
        console.log(`Function map built: ${this.functions.length} functions found`);

        if (this.functions.length === 0) {
            console.warn("No functions found! Checking instruction types:");
            const mnemonicCounts = new Map();
            for (const inst of this.instructions) {
                const m = inst.mnemonic;
                mnemonicCounts.set(m, (mnemonicCounts.get(m) || 0) + 1);
            }
            console.log("Instruction statistics:");
            const sorted = Array.from(mnemonicCounts.entries()).sort((a,b) => b[1] - a[1]);
            sorted.slice(0, 10).forEach(([mnem, count]) => {
                console.log(`  ${mnem}: ${count}`);
            });
            this.cppLines.push('// PPDS Warning: No function prologues found.');
        }

        console.log(`Processing ${this.functions.length} functions...`);
        for (let i = 0; i < this.functions.length; i++) {
            const func = this.functions[i];
            console.log(`  Processing function ${i+1}/${this.functions.length}: ${func.name} (${func.type || 'std'}, ${func.insts?.length || 0} instructions)`);
            await this.processFunctionAsync(func);
            if (i % 5 === 0 && i > 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
        console.log("=== CppDecompiler.decompile() END ===");

        return this.cppLines.join('\n');
    }

    extractDllNames() {
        const dlls = new Set();
        if (this.imports) {
            for (const imp of this.imports) if (imp.dllName) dlls.add(imp.dllName);
        }
        if (this.strings) {
            for (const str of this.strings) {
                if (typeof str.value === 'string' && str.value.toLowerCase().endsWith('.dll')) {
                    dlls.add(str.value);
                }
            }
        }
        return [...dlls];
    }

    buildFunctionMap() {
        if (!this.instructions || this.instructions.length === 0) {
            console.log("No instructions to build function map");
            return;
        }
        
        let currentFunc = null;
        let fpoCount = 0;
        let hotpatchCount = 0;
        
        for (let i = 0; i < this.instructions.length; i++) {
            const inst = this.instructions[i];
            if (!inst) continue;
            
            const mnemonic = inst.mnemonic || '';
            const text = inst.text || '';
            const bytes = inst.bytes || '';
            
            // 1. Стандартний пролог з RBP
            const isStdPrologue = mnemonic === 'push' && 
                                   (text.includes('rbp') || text.includes('ebp'));
            
            // 2. FPO пролог: push rbx/rsi/rdi (збереження регістрів)
            const isFpoPush = mnemonic === 'push' && 
                              (text.includes('rbx') || text.includes('rsi') || 
                               text.includes('rdi') || text.includes('rcx'));
            
            // 3. Hotpatch пролог
            const isHotpatch = bytes === '8b ff';
            
            // 4. Початок naked function (просто код без прологу)
            //    Шукаємо call/jmp/ret які не всередині іншої функції
            const isNakedStart = (mnemonic === 'call' || mnemonic === 'jmp') && 
                                 i > 0 && this.instructions[i-1]?.mnemonic === 'ret';
            
            if (isStdPrologue) {
                currentFunc = { 
                    name: `func_0x${inst.rva.toString(16)}`, 
                    start: inst.rva, 
                    insts: [],
                    type: 'std'
                };
                this.functions.push(currentFunc);
            }
            else if (isHotpatch && i + 1 < this.instructions.length) {
                const next = this.instructions[i + 1];
                if (next.mnemonic === 'push' && next.text.includes('rbp')) {
                    currentFunc = { 
                        name: `func_0x${inst.rva.toString(16)}`, 
                        start: inst.rva, 
                        insts: [],
                        type: 'hotpatch'
                    };
                    this.functions.push(currentFunc);
                    hotpatchCount++;
                    i++; // пропускаємо push rbp
                }
            }
            else if (isFpoPush && !currentFunc) {
                // Початок FPO функції
                currentFunc = { 
                    name: `fpo_func_0x${inst.rva.toString(16)}`, 
                    start: inst.rva, 
                    insts: [],
                    type: 'fpo',
                    savedRegs: []
                };
                this.functions.push(currentFunc);
                fpoCount++;
            }
            else if (isNakedStart && !currentFunc) {
                // Naked function
                currentFunc = { 
                    name: `naked_func_0x${inst.rva.toString(16)}`, 
                    start: inst.rva, 
                    insts: [],
                    type: 'naked'
                };
                this.functions.push(currentFunc);
            }
            
            if (currentFunc) {
                currentFunc.insts.push(inst);
                
                // Кінець функції
                if (mnemonic === 'ret' || 
                    (mnemonic === 'jmp' && !text.includes('call') && 
                     this.instructions[i+1]?.mnemonic !== 'call')) {
                    currentFunc = null;
                }
            }
        }
        
        console.log(`Found ${this.functions.length} functions (std: ${this.functions.filter(f => f.type === 'std').length}, FPO: ${fpoCount}, hotpatch: ${hotpatchCount}, naked: ${this.functions.filter(f => f.type === 'naked').length})`);
    }

    async processFunctionAsync(func) {
        return new Promise((resolve) => {
            setTimeout(() => {
                this.processFunction(func);
                resolve();
            }, 0);
        });
    }

    processFunction(func) {
        console.log(`\n${'='.repeat(60)}`);
        console.log(`  Processing ${func.name} (${func.type}, ${func.insts?.length} instructions)`);
        console.log(`${'='.repeat(60)}`);
        
        const core = new PCPU_Core(this.buffer);
        core.reset();
        
        if (!func.insts || func.insts.length === 0) {
            console.warn(`    Function ${func.name} has no instructions, skipping`);
            return;
        }
    
        if (func.type === 'fpo') {
            console.log(`    🔧 FPO function detected, will use FPO handling`);
            this.cppLines.push(`// FPO Function (Frame Pointer Omitted)`);
            this.cppLines.push(`// Optimized with: no RBP frame, uses RSP directly`);
        } else if (func.type === 'naked') {
            console.log(`    🔧 Naked function detected (no prolog/epilog)`);
            this.cppLines.push(`// Naked Function (no prolog/epilog)`);
        } else if (func.type === 'hotpatch') {
            console.log(`    🔧 Hotpatch-capable function (mov edi, edi)`);
            this.cppLines.push(`// Hotpatch-capable Function (mov edi, edi)`);
        }
        
        this.cppLines.push(`void ${func.name}(int64_t arg_1, int64_t arg_2) {`);
        
        let localVars = new Set();
        let bodyLines = [];
        let instructionCount = 0;
        let generatedStatements = 0;
    
        console.log(`\n  📝 Processing instructions:`);
        console.log(`  ${'-'.repeat(50)}`);
    
        for (const inst of func.insts) {
            instructionCount++;
            const instInfo = `[${instructionCount}] 0x${inst.rva.toString(16)}: ${inst.mnemonic} ${inst.text}`;
            
            try {
                if (!inst.bytes || inst.bytes.length === 0) {
                    console.log(`    ⚠️ ${instInfo} - no bytes, skipping`);
                    continue;
                }
    
                console.log(`    🔹 ${instInfo}`);
                console.log(`        Bytes: ${inst.bytes}`);
    
                core.execute({
                    mnem: inst.mnemonic,
                    bytes: inst.bytes,
                    len: inst.bytes.length,
                    rva: inst.rva,
                    text: inst.text
                });
    
                let stepStatements = [];
                while (core.statements.length > 0) {
                    let statement = core.statements.shift();
                    generatedStatements++;
                    
                    const stackMatch = statement.match(/var_rbp_minus_0x([0-9a-f]+)/i);
                    if (stackMatch) {
                        localVars.add(`    int64_t local_${stackMatch[1]};`);
                        statement = statement.replace(stackMatch[0], `local_${stackMatch[1]}`);
                    }
                    stepStatements.push(statement);
                    bodyLines.push(`    ${statement}`);
                }
                
                if (stepStatements.length > 0) {
                    console.log(`        → Generated ${stepStatements.length} statement(s):`);
                    stepStatements.forEach(s => console.log(`           ${s}`));
                } else {
                    console.log(`        → No statements generated (${inst.mnemonic})`);
                }
    
                if (inst.mnemonic === 'ret') {
                    const retStmt = `    return ${core.regs.rax.l};`;
                    bodyLines.push(retStmt);
                    console.log(`        → ${retStmt}`);
                }
            } catch (e) {
                console.error(`    ❌ ERROR at ${instInfo}: ${e.message}`);
                bodyLines.push(`    // [Decompiler Error at 0x${inst.rva.toString(16)}: ${e.message}]`);
            }
        }
        
        console.log(`\n  ${'-'.repeat(50)}`);
        console.log(`  📊 Function summary:`);
        console.log(`     Total instructions: ${instructionCount}`);
        console.log(`     Generated statements: ${generatedStatements}`);
        console.log(`     Local variables: ${localVars.size}`);
        console.log(`     Body lines: ${bodyLines.length}`);
        
        // Показуємо перші 10 рядків тіла функції
        if (bodyLines.length > 0) {
            console.log(`\n  📝 First 10 lines of generated code:`);
            bodyLines.slice(0, 10).forEach((line, idx) => {
                console.log(`     ${idx+1}: ${line}`);
            });
            if (bodyLines.length > 10) {
                console.log(`     ... and ${bodyLines.length - 10} more lines`);
            }
        } else {
            console.log(`  ⚠️ No code generated for this function!`);
        }
    
        if (localVars.size > 0) {
            console.log(`\n  📦 Local variables:`);
            Array.from(localVars).forEach(v => console.log(`     ${v}`));
            this.cppLines.push(...Array.from(localVars), "");
        }
        
        this.cppLines.push(...bodyLines);
        this.cppLines.push('}\n');
        
        console.log(`  ✅ Function ${func.name} processed\n`);
        
        // Скидаємо стан CPU для наступної функції
        core.savedRegs = [];
        core.stackSize = 0;
    }
}

class PCPU_Core {
    constructor(binaryBuffer) {
        if (typeof GUECMan !== 'undefined') {
            GUECMan.ConnectToClass(this);
        }
        this.buffer = binaryBuffer;
        this.ip = 0;
        this.statements = [];
        this.regs = {
            rax: {v: 0, l: "rax"}, rbx: {v: 0, l: "rbx"}, rcx: {v: 0, l: "rcx"},
            rdx: {v: 0, l: "rdx"}, rsi: {v: 0, l: "rsi"}, rdi: {v: 0, l: "rdi"},
            rbp: {v: 0xFF00, l: "rbp"}, rsp: {v: 0xFF00, l: "rsp"}
        };
        
        this.stack = new Map();
        this.flags = { zf: false, sf: false, lastComp: "" };
        
        // FPO support
        this.savedRegs = [];
        this.stackSize = 0; 
        
        this.hasRBPStackFrame = false;
        this.foundReturns = 0;        
        this.fpoDetected = false;
        this.opcodeTable = { 0x00: { mnem: "add", len: 2 }, 0x01: { mnem: "add", len: 2 }, 0x02: { mnem: "add", len: 2 }, 0x03: { mnem: "add", len: 2 },
        0x04: { mnem: "add", len: 2 }, 0x05: { mnem: "add", len: 5 },
        0x08: { mnem: "or", len: 2 }, 0x09: { mnem: "or", len: 2 }, 0x0A: { mnem: "or", len: 2 }, 0x0B: { mnem: "or", len: 2 },
        0x0C: { mnem: "or", len: 2 }, 0x0D: { mnem: "or", len: 5 },
        0x10: { mnem: "adc", len: 2 }, 0x11: { mnem: "adc", len: 2 }, 0x12: { mnem: "adc", len: 2 }, 0x13: { mnem: "adc", len: 2 },
        0x14: { mnem: "adc", len: 2 }, 0x15: { mnem: "adc", len: 5 },
        0x18: { mnem: "sbb", len: 2 }, 0x19: { mnem: "sbb", len: 2 }, 0x1A: { mnem: "sbb", len: 2 }, 0x1B: { mnem: "sbb", len: 2 },
        0x1C: { mnem: "sbb", len: 2 }, 0x1D: { mnem: "sbb", len: 5 },
        0x20: { mnem: "and", len: 2 }, 0x21: { mnem: "and", len: 2 }, 0x22: { mnem: "and", len: 2 }, 0x23: { mnem: "and", len: 2 },
        0x24: { mnem: "and", len: 2 }, 0x25: { mnem: "and", len: 5 },
        0x27: { mnem: "daa", len: 1 },
        0x28: { mnem: "sub", len: 2 }, 0x29: { mnem: "sub", len: 2 }, 0x2A: { mnem: "sub", len: 2 }, 0x2B: { mnem: "sub", len: 2 },
        0x2C: { mnem: "sub", len: 2 }, 0x2D: { mnem: "sub", len: 5 },
        0x2F: { mnem: "das", len: 1 },
        0x30: { mnem: "xor", len: 2 }, 0x31: { mnem: "xor", len: 2 }, 0x32: { mnem: "xor", len: 2 }, 0x33: { mnem: "xor", len: 2 },
        0x34: { mnem: "xor", len: 2 }, 0x35: { mnem: "xor", len: 5 },
        0x37: { mnem: "aaa", len: 1 },
        0x38: { mnem: "cmp", len: 2 }, 0x39: { mnem: "cmp", len: 2 }, 0x3A: { mnem: "cmp", len: 2 }, 0x3B: { mnem: "cmp", len: 2 },
        0x3C: { mnem: "cmp", len: 2 }, 0x3D: { mnem: "cmp", len: 5 },
        0x3F: { mnem: "aas", len: 1 },
        0x40: { mnem: "inc rax", len: 1 }, 0x41: { mnem: "inc rcx", len: 1 }, 0x42: { mnem: "inc rdx", len: 1 },
        0x43: { mnem: "inc rbx", len: 1 }, 0x44: { mnem: "inc rsp", len: 1 }, 0x45: { mnem: "inc rbp", len: 1 },
        0x46: { mnem: "inc rsi", len: 1 }, 0x47: { mnem: "inc rdi", len: 1 },
        0x48: { mnem: "dec rax", len: 1 }, 0x49: { mnem: "dec rcx", len: 1 }, 0x4A: { mnem: "dec rdx", len: 1 },
        0x4B: { mnem: "dec rbx", len: 1 }, 0x4C: { mnem: "dec rsp", len: 1 }, 0x4D: { mnem: "dec rbp", len: 1 },
        0x4E: { mnem: "dec rsi", len: 1 }, 0x4F: { mnem: "dec rdi", len: 1 },
        0x50: { mnem: "push rax", len: 1 }, 0x51: { mnem: "push rcx", len: 1 }, 0x52: { mnem: "push rdx", len: 1 },
        0x53: { mnem: "push rbx", len: 1 }, 0x54: { mnem: "push rsp", len: 1 }, 0x55: { mnem: "push rbp", len: 1 },
        0x56: { mnem: "push rsi", len: 1 }, 0x57: { mnem: "push rdi", len: 1 },
        0x58: { mnem: "pop rax", len: 1 }, 0x59: { mnem: "pop rcx", len: 1 }, 0x5A: { mnem: "pop rdx", len: 1 },
        0x5B: { mnem: "pop rbx", len: 1 }, 0x5C: { mnem: "pop rsp", len: 1 }, 0x5D: { mnem: "pop rbp", len: 1 },
        0x5E: { mnem: "pop rsi", len: 1 }, 0x5F: { mnem: "pop rdi", len: 1 },
        0x06: { mnem: "push es", len: 1 }, 0x07: { mnem: "pop es", len: 1 },
        0x0E: { mnem: "push cs", len: 1 }, 0x16: { mnem: "push ss", len: 1 }, 0x17: { mnem: "pop ss", len: 1 },
        0x1E: { mnem: "push ds", len: 1 }, 0x1F: { mnem: "pop ds", len: 1 },
        0x88: { mnem: "mov", len: 2 }, 0x89: { mnem: "mov", len: 2 }, 0x8A: { mnem: "mov", len: 2 }, 0x8B: { mnem: "mov", len: 2 },
        0x8C: { mnem: "mov", len: 2 }, 0x8D: { mnem: "lea", len: 2 }, 0x8E: { mnem: "mov", len: 2 },
        0x8F: { mnem: "pop", len: 2 },
        0xA0: { mnem: "mov", len: 5 }, 0xA1: { mnem: "mov", len: 5 }, 0xA2: { mnem: "mov", len: 5 }, 0xA3: { mnem: "mov", len: 5 },
        0xA4: { mnem: "movsb", len: 1 }, 0xA5: { mnem: "movsw", len: 1 },
        0xA6: { mnem: "cmpsb", len: 1 }, 0xA7: { mnem: "cmpsw", len: 1 },
        0xAA: { mnem: "stosb", len: 1 }, 0xAB: { mnem: "stosw", len: 1 },
        0xAC: { mnem: "lodsb", len: 1 }, 0xAD: { mnem: "lodsw", len: 1 },
        0xAE: { mnem: "scasb", len: 1 }, 0xAF: { mnem: "scasw", len: 1 },
        0x9A: { mnem: "call far", len: 5 },
        0xC2: { mnem: "ret", len: 3 }, 0xC3: { mnem: "ret", len: 1 },
        0xCA: { mnem: "retf", len: 3 }, 0xCB: { mnem: "retf", len: 1 },
        0xCC: { mnem: "int3", len: 1 }, 0xCD: { mnem: "int", len: 2 },
        0xCE: { mnem: "into", len: 1 }, 0xCF: { mnem: "iret", len: 1 },
        0xE0: { mnem: "loopne", len: 2 }, 0xE1: { mnem: "loope", len: 2 }, 0xE2: { mnem: "loop", len: 2 },
        0xE3: { mnem: "jcxz", len: 2 }, 0xE8: { mnem: "call", len: 5 }, 0xE9: { mnem: "jmp", len: 5 },
        0xEA: { mnem: "jmp far", len: 5 }, 0xEB: { mnem: "jmp", len: 2 },
        0x70: { mnem: "jo", len: 2 }, 0x71: { mnem: "jno", len: 2 }, 0x72: { mnem: "jb", len: 2 },
        0x73: { mnem: "jnb", len: 2 }, 0x74: { mnem: "jz", len: 2 }, 0x75: { mnem: "jnz", len: 2 },
        0x76: { mnem: "jbe", len: 2 }, 0x77: { mnem: "jnbe", len: 2 }, 0x78: { mnem: "js", len: 2 },
        0x79: { mnem: "jns", len: 2 }, 0x7A: { mnem: "jp", len: 2 }, 0x7B: { mnem: "jnp", len: 2 },
        0x7C: { mnem: "jl", len: 2 }, 0x7D: { mnem: "jnl", len: 2 }, 0x7E: { mnem: "jle", len: 2 },
        0x7F: { mnem: "jnle", len: 2 },
        0x90: { mnem: "nop", len: 1 }, 0x91: { mnem: "xchg rcx,rax", len: 1 }, 0x92: { mnem: "xchg rdx,rax", len: 1 },
        0x93: { mnem: "xchg rbx,rax", len: 1 }, 0x94: { mnem: "xchg rsp,rax", len: 1 }, 0x95: { mnem: "xchg rbp,rax", len: 1 },
        0x96: { mnem: "xchg rsi,rax", len: 1 }, 0x97: { mnem: "xchg rdi,rax", len: 1 },
        0x98: { mnem: "cbw", len: 1 }, 0x99: { mnem: "cwd", len: 1 },
        0x9B: { mnem: "fwait", len: 1 }, 0x9C: { mnem: "pushf", len: 1 }, 0x9D: { mnem: "popf", len: 1 },
        0x9E: { mnem: "sahf", len: 1 }, 0x9F: { mnem: "lahf", len: 1 },
        0xD4: { mnem: "aam", len: 2 }, 0xD5: { mnem: "aad", len: 2 },
        0xD6: { mnem: "salc", len: 1 }, 0xD7: { mnem: "xlat", len: 1 },
        0x80: { mnem: "add", len: 2 }, 0x81: { mnem: "add", len: 6 }, 0x82: { mnem: "add", len: 2 }, 0x83: { mnem: "add", len: 3 },
        0x84: { mnem: "test", len: 2 }, 0x85: { mnem: "test", len: 2 },
        0x86: { mnem: "xchg", len: 2 }, 0x87: { mnem: "xchg", len: 2 },
        0xA8: { mnem: "test", len: 2 }, 0xA9: { mnem: "test", len: 5 },
        0xC0: { mnem: "rol", len: 3 }, 0xC1: { mnem: "rol", len: 3 },
        0xC6: { mnem: "mov", len: 2 }, 0xC7: { mnem: "mov", len: 6 },
        0xFE: { mnem: "inc", len: 2 }, 0xFF: { mnem: "inc", len: 2 },
        0xF6: { mnem: "test", len: 2 }, 0xF7: { mnem: "test", len: 2 },
        0x0F: { mnem: "nop", len: 2, isTwoByte: true }};
        this.opcodeTable2Byte = { 0x00: { mnem: "sldt", len: 2 }, 0x01: { mnem: "sgdt", len: 2 },
        0x02: { mnem: "lar", len: 2 }, 0x03: { mnem: "lsl", len: 2 },
        0x04: { mnem: "loadall", len: 1 }, 0x05: { mnem: "syscall", len: 1 },
        0x06: { mnem: "clts", len: 1 }, 0x07: { mnem: "sysret", len: 1 },
        0x08: { mnem: "invd", len: 1 }, 0x09: { mnem: "wbinvd", len: 1 },
        0x0B: { mnem: "ud2", len: 1 }, 0x0D: { mnem: "prefetch", len: 2 },
        0x1F: { mnem: "nop", len: 2 }, 0x31: { mnem: "rdtsc", len: 1 },
        0x34: { mnem: "sysenter", len: 1 }, 0x35: { mnem: "sysexit", len: 1 },
        0xA2: { mnem: "cpuid", len: 1 }, 0xAF: { mnem: "imul", len: 2 },
        0xB0: { mnem: "cmpxchg", len: 2 }, 0xB1: { mnem: "cmpxchg", len: 2 },
        0xB6: { mnem: "movzx", len: 2 }, 0xB7: { mnem: "movzx", len: 2 },
        0xBE: { mnem: "movsx", len: 2 }, 0xBF: { mnem: "movsx", len: 2 },
        0xC7: { mnem: "cmpxchg8b", len: 2 }, 0xC8: { mnem: "bswap", len: 1 } };
        this.hasRBPStackFrame = false;
        this.foundReturns = 0;        
        this.fpoDetected = false;
    }

    decodeModRM(bytes) {
        const modrm = bytes[1];
        const mod = (modrm >> 6) & 3;
        const reg = (modrm >> 3) & 7;
        const rm = modrm & 7;
        const regNames = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
        
        let offset = 0;
        if (mod === 1) {
            offset = bytes[2];
            if (offset > 127) offset -= 256;
        } else if (mod === 2) {
            offset = bytes[2] | (bytes[3] << 8) | (bytes[4] << 16) | (bytes[5] << 24);
        }
        
        return {
            mod,
            regName: regNames[reg],
            rmName: regNames[rm],
            isDirect: mod === 3,
            offset: offset
        };
    }

    stackPush(data) {
        this.regs.rsp.v -= 8;
        this.stack.set(this.regs.rsp.v, data);
        this.statements.push(`// push ${data.l}`);
    }

    stackPop() {
        const data = this.stack.get(this.regs.rsp.v) || {v: 0, l: `pop_val_${this.regs.rsp.v.toString(16)}`};
        this.regs.rsp.v += 8;
        return data;
    }

    fetchNext() {
        let byte = this.buffer[this.ip];
        let instInfo;

        if (byte === 0x0F) { // Перехід до двобайтових опкодів
            this.ip++;
            byte = this.buffer[this.ip];
            instInfo = this.opcodeTable2Byte[byte] || { mnem: "db", len: 1 };
        } else {
            instInfo = this.opcodeTable[byte] || { mnem: "db", len: 1 };
        }

        // Отримуємо сирі байти інструкції для аналізу ModR/M (якщо треба)
        const rawInst = this.buffer.slice(this.ip, this.ip + instInfo.len);
        
        this.ip += instInfo.len;
        return { ...instInfo, bytes: rawInst };
    }

    run(steps = 100) {
        for (let i = 0; i < steps; i++) {
            const inst = this.fetchNext();
            if (inst.mnem === "ret") break;
            
            this.execute(inst);
        }
    }

    resolveAddress(m) {
        if (m.rmName === 'rsp' && this.savedRegs.length > 0) {
            return `[rbp-0x${(this.savedRegs.length * 8).toString(16)}]`;
        }
        
        if (m.offset !== undefined) {
            return `[${m.rmName}+0x${m.offset.toString(16)}]`;
        }
        
        return `[${m.rmName}]`;
    }

    reset() {
        this.ip = 0;
        this.statements = [];
        this.regs = {
            rax: {v: 0, l: "rax"}, rbx: {v: 0, l: "rbx"}, 
            rcx: {v: 0, l: "rcx"}, rdx: {v: 0, l: "rdx"},
            rsi: {v: 0, l: "rsi"}, rdi: {v: 0, l: "rdi"},
            rbp: {v: 0xFF00, l: "rbp"}, rsp: {v: 0xFF00, l: "rsp"}
        };
        this.stack.clear();
        this.flags = { zf: false, sf: false, lastComp: "" };
        this.savedRegs = [];
        this.stackSize = 0;
        this.hasRBPStackFrame = false;
        this.foundReturns = 0;
    }

    execute(inst) {
        const bytes = inst.bytes;
        const mnem = inst.mnem;
        const op0 = inst.bytes[0];

        const debugMnemonics = ['push', 'pop', 'call', 'ret', 'mov', 'lea', 'add', 'sub', 'jmp', 'jz', 'jnz'];
        if (debugMnemonics.includes(mnem)) {
            console.log(`        [CPU] Executing: ${mnem} ${Array.from(bytes).map(b => '0x'+b.toString(16)).join(' ')}`);
        }
    
        if (op0 === 0x55 || (mnem === 'push' && inst.bytes.includes(0x55))) {
            this.hasRBPStackFrame = true;
        }
    
        if (mnem === 'ret') {
            this.foundReturns++;
        }
    
        switch (mnem) {
            case 'movq':  // 64-bit mov
            case 'addq':  // 64-bit add
            case 'subq':  // 64-bit sub
            case 'xorq':  // 64-bit xor
            case 'andq':  // 64-bit and
            case 'orq':   // 64-bit or
                const q = this.decodeModRM(bytes);
                const opSymQ = { 'addq': '+', 'subq': '-', 'xorq': '^', 'andq': '&', 'orq': '|' }[mnem];
                if (mnem === 'xorq' && q.regName === q.rmName) {
                    this.regs[q.regName] = { v: 0, l: "0" };
                } else {
                    this.regs[q.regName].l = `(${this.regs[q.regName].l} ${opSymQ} ${this.regs[q.rmName].l})`;
                }
                break;
            case 'js':   // sign
                this.statements.push(`if ((${this.flags.lastComp}) < 0) goto label_0x...;`);
                break;
            case 'jns':  // not sign
                this.statements.push(`if ((${this.flags.lastComp}) >= 0) goto label_0x...;`);
                break;
            case 'jle':  // less or equal
                this.statements.push(`if ((${this.flags.lastComp}) <= 0) goto label_0x...;`);
                break;
            case 'jg':   // greater
                this.statements.push(`if ((${this.flags.lastComp}) > 0) goto label_0x...;`);
                break;
            case 'jbe':  // below or equal
                this.statements.push(`if ((${this.flags.lastComp}) <= 0) goto label_0x...;`);
                break;
            case 'ja':   // above
                this.statements.push(`if ((${this.flags.lastComp}) > 0) goto label_0x...;`);
                break;
            case 'xchg':
                const x = this.decodeModRM(bytes);
                const temp = this.regs[x.regName].l;
                this.regs[x.regName].l = this.regs[x.rmName].l;
                this.regs[x.rmName].l = temp;
                break;
            case 'loop':
                this.regs.rcx.l = `(${this.regs.rcx.l} - 1)`;
                this.statements.push(`if (${this.regs.rcx.l} != 0) goto label_0x...;`);
                break;
            case 'loopne':
                this.regs.rcx.l = `(${this.regs.rcx.l} - 1)`;
                this.statements.push(`if (${this.regs.rcx.l} != 0 && ${this.flags.lastComp} != 0) goto label_0x...;`);
                break;
            case 'loope':
                this.regs.rcx.l = `(${this.regs.rcx.l} - 1)`;
                this.statements.push(`if (${this.regs.rcx.l} != 0 && ${this.flags.lastComp} == 0) goto label_0x...;`);
                break;
            case 'rol':
            case 'ror':
            case 'rcl':
            case 'rcr':
                this.statements.push(`// ${inst.text}`);
                break;
            case 'scasb':
            case 'scasw':
            case 'scasd':
            case 'scasq':
                this.statements.push(`// ${inst.text} (string scan)`);
                break;
            case 'lodsb':
            case 'lodsw':
            case 'lodsd':
            case 'lodsq':
                this.statements.push(`// ${inst.text} (load string)`);
                break;
            case 'cmpsb':
            case 'cmpsw':
            case 'cmpsd':
            case 'cmpsq':
                this.statements.push(`// ${inst.text} (compare string)`);
                break;
            case 'rex.48':
            case 'rex.4c':
            case 'rex.4d':
            case 'rex.41':
            case 'rex.4b':
            case 'rex.4f':
            case 'rex.43':
            case 'rex.45':
                // just ignore
                break;
            case 'mov':
            case 'movzx':
            case 'movsx': {
                const m = this.decodeModRM(bytes);
                
                if (!m.isDirect && m.rmName === 'rsp' && this.savedRegs.length > 0) {
                    const savedOffset = this.savedRegs.length * 8;
                    const finalOffset = savedOffset - (m.offset || 0);
                    const regName = m.regName;
                    this.statements.push(`; FPO: [rbp-0x${finalOffset.toString(16)}] = ${this.regs[regName].l}`);
                    break;
                }
                
                if (m.isDirect) {
                    this.regs[m.rmName] = { ...this.regs[m.regName] };
                } else {
                    const addr = this.resolveAddress(m);
                    this.statements.push(`${addr} = ${this.regs[m.regName].l};`);
                }
                break;
            }
    
            case 'lea': {
                const l = this.decodeModRM(bytes);
                
                // FPO: lea rbx, [rsp+0x20] -> lea rbx, [rbp-0x?]
                if (l.rmName === 'rsp' && this.savedRegs.length > 0) {
                    const savedOffset = this.savedRegs.length * 8;
                    const finalOffset = savedOffset - (l.offset || 0);
                    this.regs[l.regName] = { v: 0, l: `&var_rbp_minus_0x${finalOffset.toString(16)}` };
                    this.statements.push(`; FPO: ${l.regName} = rbp - 0x${finalOffset.toString(16)}`);
                    break;
                }
                
                if (l.offset !== 0) {
                    this.regs[l.regName] = { v: 0, l: `&var_${l.rmName}_plus_0x${l.offset.toString(16)}` };
                } else {
                    this.regs[l.regName] = { v: 0, l: `&var_${l.rmName}` };
                }
                break;
            }
    
            case 'add':
            case 'sub':
            case 'xor':
            case 'and':
            case 'or':
            case 'adc':
            case 'sbb':
            case 'imul': {
                const a = this.decodeModRM(bytes);
                const opSym = { 'add': '+', 'sub': '-', 'xor': '^', 'and': '&', 'or': '|', 'adc': '+ [cf] +', 'sbb': '- [cf] -', 'imul': '*' }[mnem];
                
                if (mnem === 'sub' && a.regName === 'rsp') {
                    const sizeMatch = inst.text && inst.text.match(/0x([0-9a-f]+)/i);
                    if (sizeMatch) {
                        this.stackSize += parseInt(sizeMatch[1], 16);
                        this.statements.push(`; FPO: allocate ${sizeMatch[1]} bytes on stack (total: ${this.stackSize})`);
                    }
                    break;
                }
                
                if (mnem === 'add' && a.regName === 'rsp') {
                    const sizeMatch = inst.text && inst.text.match(/0x([0-9a-f]+)/i);
                    if (sizeMatch) {
                        this.stackSize -= parseInt(sizeMatch[1], 16);
                        this.statements.push(`; FPO: free ${sizeMatch[1]} bytes from stack (remaining: ${this.stackSize})`);
                    }
                    break;
                }
                
                if (mnem === 'xor' && a.regName === a.rmName) {
                    this.regs[a.regName] = { v: 0, l: "0" };
                } else {
                    this.regs[a.regName].l = `(${this.regs[a.regName].l} ${opSym} ${this.regs[a.rmName].l})`;
                }
                break;
            }
            
            case 'push': {
                const regMatch = inst.text && inst.text.match(/push (r[a-z]+)/i);
                if (regMatch && !regMatch[1].includes('bp')) {
                    this.savedRegs.unshift(regMatch[1]);
                    this.statements.push(`; FPO: save ${regMatch[1]} (will restore at epilog)`);
                }

                const pVal = (op0 >= 0x50 && op0 <= 0x57) 
                    ? this.regs[['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][op0 - 0x50]]
                    : this.regs[this.decodeModRM(bytes).regName];
                this.stackPush(pVal);
                break;
            }
    
            case 'pop': {
                const targetPop = (op0 >= 0x58 && op0 <= 0x5F)
                    ? ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][op0 - 0x58]
                    : this.decodeModRM(bytes).regName;
                    
                if (this.savedRegs.length > 0 && this.savedRegs[0] === targetPop) {
                    this.savedRegs.shift();
                    this.statements.push(`; FPO: restore ${targetPop}`);
                }
                
                this.regs[targetPop] = this.stackPop();
                break;
            }
            
            case 'inc':
            case 'dec': {
                const sign = mnem === 'inc' ? '++' : '--';
                const regIdx = op0 >= 0x40 && op0 <= 0x4F ? (op0 & 7) : -1;
                const target = regIdx !== -1 ? ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][regIdx] : this.decodeModRM(bytes).regName;
                this.regs[target].l = `(${this.regs[target].l}${sign})`;
                break;
            }
    
            case 'cmp':
            case 'test': {
                const c = this.decodeModRM(bytes);
                this.flags.lastComp = `${this.regs[c.regName].l} == ${this.regs[c.rmName].l}`;
                break;
            }
    
            case 'jz': 
            case 'jnz': 
            case 'jl': 
            case 'jg': 
            case 'jb': 
            case 'jbe': {
                const condMap = { 'jz':'==', 'jnz':'!=', 'jl':'<', 'jg':'>', 'jb':'<', 'jbe':'<=' };
                this.statements.push(`if (${this.flags.lastComp} ${condMap[mnem]} 0) goto label_0x...;`);
                break;
            }
    
            case 'jmp':
                this.statements.push(`goto label_0x...;`);
                break;
    
            case 'call':
                this.statements.push(`func_${this.ip.toString(16)}(/* arguments */);`);
                this.regs.rax = { v: 0, l: `last_call_res` };
                break;
    
            case 'ret': {
                for (let i = this.savedRegs.length - 1; i >= 0; i--) {
                    this.statements.push(`    pop ${this.savedRegs[i]}                ; restore saved register`);
                }
                if (this.stackSize > 0) {
                    this.statements.push(`    add rsp, ${this.stackSize}            ; free stack space`);
                }
                this.statements.push(`    pop rbp                 ; restore frame pointer`);
                this.statements.push(`    return ${this.regs.rax.l};`);
                break;
            }
    
            case 'movsb':
            case 'movsw':
                this.statements.push(`memcpy(rdi, rsi, ${mnem === 'movsb' ? 1 : 2});`);
                break;
    
            case 'cpuid':
                this.regs.rax = { v: 0, l: '"GenuineIntel"' };
                break;
    
            case 'rdtsc':
                this.regs.rax = { v: Date.now(), l: 'timestamp_low' };
                this.regs.rdx = { v: 0, l: 'timestamp_high' };
                break;
    
            case 'nop':
                break;
    
            case 'int3':
                this.statements.push(`// int3 breakpoint (0x${inst.rva?.toString(16) || '?'})`);
                break;
                
            case 'int': {
                const intNum = bytes[1] || 0;
                if (intNum === 3) {
                    this.statements.push(`// int 3 breakpoint`);
                } else {
                    this.statements.push(`// int ${intNum} (software interrupt)`);
                }
                break;
            }
    
            case 'db':
                this.statements.push(`// db ${Array.from(bytes).map(b => '0x' + b.toString(16)).join(', ')}`);
                break;
    
            default:
                if (mnem !== 'int3' && mnem !== 'db' && mnem !== '???') {
                    this.statements.push(`// C++ JSCPU Decomp Warning: Unknown operation ${mnem}`);
                }
                break;
        }
    }

    getDecompilerHeader() {
        this.fpoDetected = this.foundReturns > 0 && !this.hasRBPStackFrame;
        
        let report = "// Generated by RSDEFD C++ Decompiler v2.0\n";
        report += "// Decompiled C++ based by JS CPU calculations\n";
        
        if (this.fpoDetected) {
            report += "// C++ JSCPU Decomp: This Portable Executable contains FPO (Frame Pointer Omission)\n";
            report += "// ⚠️ Warning: Standard stack frame analysis (RBP-based) is disabled.\n";
        }

        return report;
    }
}

class FPODeoptimizer {
    constructor(instructions, bytes) {
        this.instructions = instructions;
        this.bytes = bytes;
        this.deoptimized = [];
        this.functions = [];
        this.stackOffsets = new Map();
        this.regs = {
            rax: 'rax', rbx: 'rbx', rcx: 'rcx', rdx: 'rdx',
            rsi: 'rsi', rdi: 'rdi', rsp: 'rsp', rbp: 'rbp'
        };
    }

    deoptimize() {
        this.analyzeFunctionBoundaries();
        
        for (const func of this.functions) {
            const decompiled = this.deoptimizeFunction(func);
            this.deoptimized.push(...decompiled);
        }
        
        return this.deoptimized;
    }

    analyzeFunctionBoundaries() {
        let currentFunc = null;
        
        for (let i = 0; i < this.instructions.length; i++) {
            const inst = this.instructions[i];
            if (!inst) continue;
            
            const isHotpatch = inst.bytes === '8b ff'; // mov edi, edi
            const isPushReg = inst.mnemonic === 'push' && 
                              (inst.text.includes('rbx') || inst.text.includes('rsi') || 
                               inst.text.includes('rdi') || inst.text.includes('rcx') ||
                               inst.text.includes('rdx') || inst.text.includes('rax'));
            const isSubRsp = inst.mnemonic === 'sub' && inst.text.includes('rsp');
            const isStdPrologue = inst.mnemonic === 'push' && 
                                  (inst.text.includes('rbp') || inst.text.includes('ebp'));
            
            if (isStdPrologue) {
                currentFunc = { start: i, insts: [], type: 'std', savedRegs: [] };
                this.functions.push(currentFunc);
            } 
            else if (isHotpatch && i + 1 < this.instructions.length) {
                const next = this.instructions[i + 1];
                if (next.mnemonic === 'push' && next.text.includes('rbp')) {
                    currentFunc = { start: i, insts: [], type: 'hotpatch', savedRegs: [] };
                    this.functions.push(currentFunc);
                    i++;
                }
            }
            else if (isPushReg && i + 1 < this.instructions.length) {
                const next = this.instructions[i + 1];
                if (next.mnemonic === 'push' || next.mnemonic === 'sub') {
                    currentFunc = { 
                        start: i, 
                        insts: [], 
                        type: 'fpo', 
                        savedRegs: [],
                        stackSize: 0
                    };
                    this.functions.push(currentFunc);
                }
            }
            
            if (currentFunc) {
                currentFunc.insts.push(inst);
                
                if (inst.mnemonic === 'ret' || 
                    (inst.mnemonic === 'jmp' && !inst.text.includes('call'))) {
                    currentFunc.end = i;
                    currentFunc = null;
                }
            }
        }
        
        console.log(`Found ${this.functions.length} functions (${this.functions.filter(f => f.type === 'std').length} std, ${this.functions.filter(f => f.type === 'fpo').length} FPO, ${this.functions.filter(f => f.type === 'hotpatch').length} hotpatch)`);
    }

    deoptimizeFunction(func) {
        const lines = [];
        
        lines.push(`; === Function at 0x${func.insts[0]?.rva?.toString(16) || '?'} (${func.type}) ===`);
        lines.push(`func_${func.insts[0]?.rva?.toString(16) || '0'}:`);
        
        lines.push(`    push rbp                 ; restored prolog`);
        lines.push(`    mov rbp, rsp             ; set stack frame`);
        
        let savedRegs = [];
        let stackOffset = 0;
        
        for (let i = 0; i < func.insts.length; i++) {
            const inst = func.insts[i];
            let asm = this.restoreInstruction(inst, savedRegs, stackOffset);
            
            if (func.type === 'fpo' && inst.mnemonic === 'push') {
                const regMatch = inst.text.match(/push (r[a-z]+)/i);
                if (regMatch) {
                    savedRegs.push(regMatch[1]);
                    asm = `; FPO push ${regMatch[1]} -> will restore at epilog`;
                    stackOffset += 8;
                }
            }
            
            if (inst.mnemonic === 'sub' && inst.text.includes('rsp')) {
                const sizeMatch = inst.text.match(/0x([0-9a-f]+)/i);
                if (sizeMatch) {
                    stackOffset += parseInt(sizeMatch[1], 16);
                    asm = `; FPO allocate ${sizeMatch[1]} bytes on stack`;
                }
            }
            
            if (inst.mnemonic === 'ret') {
                for (let j = savedRegs.length - 1; j >= 0; j--) {
                    lines.push(`    pop ${savedRegs[j]}                ; restore saved register`);
                }
                if (stackOffset > 0) {
                    lines.push(`    add rsp, ${stackOffset}            ; free stack space`);
                }
                lines.push(`    pop rbp                 ; restore frame pointer`);
                asm = `    ret                     ; return`;
            }
            
            lines.push(asm);
        }
        
        lines.push('');
        return lines;
    }

    restoreInstruction(inst, savedRegs, stackOffset) {
        let asm = `    ${inst.text}`;
        
        if (inst.text.includes('[rsp+') || inst.text.includes('[rsp-')) {
            const rspMatch = inst.text.match(/\[rsp([+-]0x[0-9a-f]+)\]/i);
            if (rspMatch) {
                let offset = parseInt(rspMatch[1], 16);
                const savedOffset = savedRegs.length * 8;
                const newOffset = offset - savedOffset;
                asm = asm.replace(/\[rsp[+-]0x[0-9a-f]+\]/, `[rbp-0x${(-newOffset).toString(16)}]`);
            }
        }
        
        if (inst.text.includes('[') && !inst.text.includes('rbp') && !inst.text.includes('rsp')) {
            asm = asm.replace(/\[(0x[0-9a-f]+)\]/g, (match, addr) => {
                return `[rip + ${addr}]`;
            });
        }
        
        return asm;
    }
}

// Browser API lib
if (typeof window !== 'undefined') {
    window.RSDEFD = { Scanner: RSDEFD };
}

// Node.js Lib
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { RSDEFD };
}

/*
    GUEC Manager, Global Unhandled Exception Catcher, connectable to class manager
    Copyright (C) 2026 RedstoneShell. All rights reserved
 */


class GUECManager {
    constructor() {
        this.connectedClasses = new Set();
        this.initGlobalHandlers();
    }

    initGlobalHandlers() {
        window.onerror = (msg, url, line, col, error) => {
            this.reportError("RUNTIME ERROR", { msg, line, col, stack: error?.stack });
            return false;
        };

        window.onunhandledrejection = (event) => {
            this.reportError("PROMISE REJECTION", { msg: event.reason });
        };
    }

    ConnectToClass(instance) {
        console.log(`%c [GUEC] Connected to ${instance.constructor.name} `, "background: #222; color: #bada55");
        
        instance._guec_active = true;
        this.connectedClasses.add(instance);
    }

    reportError(type, data) {
        console.group("%c 🚨 GUEC PROTECTOR: " + type, "color: red; font-weight: bold;");
        console.table(data);
        
        this.connectedClasses.forEach(inst => {
            if (inst.regs) {
                console.log(`%c [CPU Snapshot] Last IP: 0x${inst.ip?.toString(16)}`, "color: #00ff00");
                console.dir(inst.regs);
            }
            if (inst.instructions) { 
                console.log(`[Decompiler State] Instructions loaded: ${inst.instructions.length}`);
            }
        });
    
        if (data.msg && data.msg.includes("BigInt")) {
            console.warn("💡 Hint: Check if you are mixing BigInt and Number in RVA/Offset calculations!");
            console.log("Check variables: imageBase, virtualAddress, and instruction.rva");
        }
        console.groupEnd();
    }
}

// Створюємо глобальний екземпляр
const GUECMan = new GUECManager();
