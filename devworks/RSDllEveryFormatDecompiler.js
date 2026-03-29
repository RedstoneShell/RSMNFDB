/*
    Made by RedstoneShell, provided by RedstoneShell Microsoft Not-documented Functions DB
    RSDEFD - RedstoneShell Dll Every Format Decompiler. Usiversal research decompiler x64-86, no giant formulas justification,
    you see all! 
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
            const fileName = this.options.fileName || "";
            if (fileName.includes('7B296FB0')) {
                console.log("Windows Software Licensing file detected");
                await this.scanWindowsLicense();
                this.result.success = true;
                return this.result;
            }
            if (this.options.fileExt==="vp") {
                console.log("Intel VP container detected");
                this.report = {
                    fileInfo: { size: this.bytes.length, name: this.options.fileName || "Unknown" },
                    sections: [],
                };
                await this.scanIntelVP();
                this.result.success = true;
                this.result.summary = {
                    fileName: this.options.fileName || "Unknown",
                    size: this.bytes.length,
                    type: "Intel VP Container",
                    sections: this.findVPSections().length,
                    embeddedFiles: this.findEmbeddedPEFiles().length
                };
                return this.result;
            }
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
        }, 50000);
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
                const decompiler = new CppDecompiler(
                    this.bytes, 
                    allInstructions, 
                    this.report.imports, 
                    strings,
                    this.report.sections
                );
                
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
        let consecutiveData = 0;
        let inDataSection = false;
        
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
            0x60: { mnem: "pusha", len: 1 }, 0x61: { mnem: "popa", len: 1 },
            0x62: { mnem: "bound", len: 2 }, 0x63: { mnem: "arpl", len: 2 },
            0x64: { mnem: "fs", len: 1 },  // prefix
            0x65: { mnem: "gs", len: 1 },  // prefix
            0x66: { mnem: "data16", len: 1 }, // prefix
            0x67: { mnem: "addr16", len: 1 }, // prefix
            0x68: { mnem: "push", len: 5 }, 0x69: { mnem: "imul", len: 6 }, 0x6A: { mnem: "push", len: 2 },
            0x6B: { mnem: "imul", len: 3 }, 0x6C: { mnem: "insb", len: 1 }, 0x6D: { mnem: "insw", len: 1 },
            0x6E: { mnem: "outsb", len: 1 }, 0x6F: { mnem: "outsw", len: 1 },
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
            0x0F: { mnem: "nop", len: 2, isTwoByte: true },
            0xD8: { mnem: "fadd", len: 2 }, 0xD9: { mnem: "fld", len: 2 },
            0xDA: { mnem: "fcmovb", len: 2 }, 0xDB: { mnem: "fild", len: 2 },
            0xDC: { mnem: "fadd", len: 2 }, 0xDD: { mnem: "fld", len: 2 },
            0xDE: { mnem: "faddp", len: 2 }, 0xDF: { mnem: "fild", len: 2 },
            0x0F: { mnem: "nop", len: 2, isTwoByte: true },
            0xF0: { mnem: "lock", len: 1 }, // prefix
            0xF2: { mnem: "repne", len: 1 }, // prefix
            0xF3: { mnem: "repe", len: 1 },  // prefix
            0xF4: { mnem: "hlt", len: 1 },
            0xF5: { mnem: "cmc", len: 1 },
            0xF8: { mnem: "clc", len: 1 },
            0xF9: { mnem: "stc", len: 1 },
            0xFA: { mnem: "cli", len: 1 },
            0xFB: { mnem: "sti", len: 1 },
            0xFC: { mnem: "cld", len: 1 },
            0xFD: { mnem: "std", len: 1 },
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
            0xC7: { mnem: "cmpxchg8b", len: 2 }, 0xC8: { mnem: "bswap", len: 1 },
            0x80: { mnem: "jo", len: 5 }, 0x81: { mnem: "jno", len: 5 }, 0x82: { mnem: "jb", len: 5 }, 0x83: { mnem: "jnb", len: 5 }, 0x84: { mnem: "jz", len: 5 }, 0x85: { mnem: "jnz", len: 5 }, 0x86: { mnem: "jbe", len: 5 }, 0x87: { mnem: "jnbe", len: 5 }, 0x88: { mnem: "js", len: 5 }, 0x89: { mnem: "jns", len: 5 }, 0x8A: { mnem: "jp", len: 5 }, 0x8B: { mnem: "jnp", len: 5 }, 0x8C: { mnem: "jl", len: 5 }, 0x8D: { mnem: "jnl", len: 5 }, 0x8E: { mnem: "jle", len: 5 }, 0x8F: { mnem: "jnle", len: 5 },
            0x40: { mnem: "cmovno", len: 2 }, 0x41: { mnem: "cmovno", len: 2 }, 0x42: { mnem: "cmovb", len: 2 },  0x43: { mnem: "cmovnb", len: 2 }, 0x44: { mnem: "cmovz", len: 2 },  0x45: { mnem: "cmovnz", len: 2 }, 0x46: { mnem: "cmovbe", len: 2 }, 0x47: { mnem: "cmovnbe", len: 2 }, 0x48: { mnem: "cmovs", len: 2 },  0x49: { mnem: "cmovns", len: 2 }, 0x4A: { mnem: "cmovp", len: 2 },  0x4B: { mnem: "cmovnp", len: 2 }, 0x4C: { mnem: "cmovl", len: 2 },  0x4D: { mnem: "cmovnl", len: 2 }, 0x4E: { mnem: "cmovle", len: 2 }, 0x4F: { mnem: "cmovnle", len: 2 },
            0x10: { mnem: "movups", len: 2 }, 0x11: { mnem: "movups", len: 2 }, 0x12: { mnem: "movlps", len: 2 }, 0x13: { mnem: "movlps", len: 2 },
            0x14: { mnem: "unpcklps", len: 2 }, 0x15: { mnem: "unpckhps", len: 2 }, 0x16: { mnem: "movhps", len: 2 }, 0x17: { mnem: "movhps", len: 2 },
            0x28: { mnem: "movaps", len: 2 }, 0x29: { mnem: "movaps", len: 2 }, 0x2A: { mnem: "cvtpi2ps", len: 2 }, 0x2B: { mnem: "movntps", len: 2 },
            0x2C: { mnem: "cvttps2pi", len: 2 }, 0x2D: { mnem: "cvtps2pi", len: 2 }, 0x2E: { mnem: "ucomiss", len: 2 }, 0x2F: { mnem: "comiss", len: 2 },
            0x50: { mnem: "movmskps", len: 2 }, 0x51: { mnem: "sqrtps", len: 2 }, 0x52: { mnem: "rsqrtps", len: 2 }, 0x53: { mnem: "rcpps", len: 2 },
            0x54: { mnem: "andps", len: 2 }, 0x55: { mnem: "andnps", len: 2 }, 0x56: { mnem: "orps", len: 2 }, 0x57: { mnem: "xorps", len: 2 },
            0x58: { mnem: "addps", len: 2 }, 0x59: { mnem: "mulps", len: 2 }, 0x5A: { mnem: "cvtps2pd", len: 2 }, 0x5B: { mnem: "cvtdq2ps", len: 2 },
            0x5C: { mnem: "subps", len: 2 }, 0x5D: { mnem: "minps", len: 2 }, 0x5E: { mnem: "divps", len: 2 }, 0x5F: { mnem: "maxps", len: 2 },
            0x01: { mnem: "sgdt", len: 2 },
            0x08: { mnem: "invd", len: 1 }, 0x09: { mnem: "wbinvd", len: 1 }, 0x0B: { mnem: "ud2", len: 1 }, 0x1F: { mnem: "nop", len: 2 },
            0x30: { mnem: "wrmsr", len: 1 }, 0x31: { mnem: "rdtsc", len: 1 }, 0x32: { mnem: "rdmsr", len: 1 }, 0x33: { mnem: "rdpmc", len: 1 }, 0x34: { mnem: "sysenter", len: 1 }, 0x35: { mnem: "sysexit", len: 1 }, 0x40: { mnem: "cmovo", len: 2 },
            0x41: { mnem: "cmovno", len: 2 }, 0x42: { mnem: "cmovb", len: 2 }, 0x43: { mnem: "cmovnb", len: 2 }, 0x44: { mnem: "cmovz", len: 2 }, 0x45: { mnem: "cmovnz", len: 2 }, 0x46: { mnem: "cmovbe", len: 2 }, 0x47: { mnem: "cmovnbe", len: 2 }, 0x48: { mnem: "cmovs", len: 2 },
            0x49: { mnem: "cmovns", len: 2 }, 0x4A: { mnem: "cmovp", len: 2 }, 0x4B: { mnem: "cmovnp", len: 2 }, 0x4C: { mnem: "cmovl", len: 2 }, 0x4D: { mnem: "cmovnl", len: 2 }, 0x4E: { mnem: "cmovle", len: 2 }, 0x4F: { mnem: "cmovnle", len: 2 },
            0x80: { mnem: "jo", len: 5 },  0x81: { mnem: "jno", len: 5 },  0x82: { mnem: "jb", len: 5 },  0x83: { mnem: "jnb", len: 5 },  0x84: { mnem: "jz", len: 5 },  0x85: { mnem: "jnz", len: 5 },  0x86: { mnem: "jbe", len: 5 },  0x87: { mnem: "jnbe", len: 5 },
            0x88: { mnem: "js", len: 5 },  0x89: { mnem: "jns", len: 5 },  0x8A: { mnem: "jp", len: 5 },  0x8B: { mnem: "jnp", len: 5 },  0x8C: { mnem: "jl", len: 5 },  0x8D: { mnem: "jnl", len: 5 },  0x8E: { mnem: "jle", len: 5 },  0x8F: { mnem: "jnle", len: 5 },  0x90: { mnem: "seto", len: 2 },  0x91: { mnem: "setno", len: 2 },  0x92: { mnem: "setb", len: 2 },  0x93: { mnem: "setnb", len: 2 },  0x94: { mnem: "setz", len: 2 },
            0x95: { mnem: "setnz", len: 2 }, 0x96: { mnem: "setbe", len: 2 }, 0x97: { mnem: "setnbe", len: 2 }, 0x98: { mnem: "sets", len: 2 }, 0x99: { mnem: "setns", len: 2 }, 0x9A: { mnem: "setp", len: 2 }, 0x9B: { mnem: "setnp", len: 2 }, 0x9C: { mnem: "setl", len: 2 },
            0x9D: { mnem: "setnl", len: 2 }, 0x9E: { mnem: "setle", len: 2 }, 0x9F: { mnem: "setnle", len: 2 }, 0xA0: { mnem: "push fs", len: 1 }, 0xA1: { mnem: "pop fs", len: 1 }, 0xA2: { mnem: "cpuid", len: 1 }, 0xA3: { mnem: "bt", len: 2 }, 0xA4: { mnem: "shld", len: 3 }, 0xA5: { mnem: "shld", len: 2 },
            0xA8: { mnem: "push gs", len: 1 }, 0xA9: { mnem: "pop gs", len: 1 }, 0xAA: { mnem: "rsm", len: 1 }, 0xAB: { mnem: "bts", len: 2 }, 0xAC: { mnem: "shrd", len: 3 }, 0xAD: { mnem: "shrd", len: 2 }, 0xAE: { mnem: "fxsave", len: 2 }, 0xAF: { mnem: "imul", len: 2 }, 0xB0: { mnem: "cmpxchg", len: 2 }, 0xB1: { mnem: "cmpxchg", len: 2 },
            0xB2: { mnem: "lss", len: 2 },  0xB3: { mnem: "btr", len: 2 },  0xB4: { mnem: "lfs", len: 2 },  0xB5: { mnem: "lgs", len: 2 },  0xB6: { mnem: "movzx", len: 2 },  0xB7: { mnem: "movzx", len: 2 },  0xB8: { mnem: "popcnt", len: 2 },  0xB9: { mnem: "ud1", len: 2 },  0xBA: { mnem: "bt", len: 3 },  0xBB: { mnem: "btc", len: 2 },
            0xBC: { mnem: "bsf", len: 2 }, 0xBD: { mnem: "bsr", len: 2 }, 0xBE: { mnem: "movsx", len: 2 }, 0xBF: { mnem: "movsx", len: 2 }, 0xC0: { mnem: "xadd", len: 2 }, 0xC1: { mnem: "xadd", len: 2 }, 0xC2: { mnem: "cmpps", len: 3 }, 0xC3: { mnem: "movnti", len: 2 }, 0xC4: { mnem: "pinsrw", len: 3 }, 0xC5: { mnem: "pextrw", len: 3 },
            0xC6: { mnem: "shufps", len: 3 },  0xC7: { mnem: "cmpxchg8b", len: 2 },  0xC8: { mnem: "bswap", len: 1 },  0xC9: { mnem: "bswap", len: 1 },  0xCA: { mnem: "bswap", len: 1 },  0xCB: { mnem: "bswap", len: 1 },  0xCC: { mnem: "bswap", len: 1 },  0xCD: { mnem: "bswap", len: 1 },  0xCE: { mnem: "bswap", len: 1 },
            0xCF: { mnem: "bswap", len: 1 }, 0xD0: { mnem: "addsubps", len: 2 }, 0xD1: { mnem: "psrlw", len: 2 }, 0xD2: { mnem: "psrld", len: 2 }, 0xD3: { mnem: "psrlq", len: 2 }, 0xD4: { mnem: "paddq", len: 2 }, 0xD5: { mnem: "pmullw", len: 2 }, 0xD6: { mnem: "movq", len: 2 }, 0xD7: { mnem: "pmovmskb", len: 2 },
            0xD8: { mnem: "psubusb", len: 2 }, 0xD9: { mnem: "psubusw", len: 2 }, 0xDA: { mnem: "pminub", len: 2 }, 0xDB: { mnem: "pand", len: 2 }, 0xDC: { mnem: "paddusb", len: 2 }, 0xDD: { mnem: "paddusw", len: 2 }, 0xDE: { mnem: "pmaxub", len: 2 }, 0xDF: { mnem: "pandn", len: 2 }, 0xE0: { mnem: "pavgb", len: 2 },
            0xE1: { mnem: "psraw", len: 2 }, 0xE2: { mnem: "psrad", len: 2 }, 0xE3: { mnem: "pavgw", len: 2 }, 0xE4: { mnem: "pmulhuw", len: 2 }, 0xE5: { mnem: "pmulhw", len: 2 }, 0xE6: { mnem: "cvttpd2dq", len: 2 }, 0xE7: { mnem: "movntq", len: 2 }, 0xE8: { mnem: "psubsb", len: 2 }, 0xE9: { mnem: "psubsw", len: 2 }, 0xEA: { mnem: "pminsw", len: 2 }, 0xEB: { mnem: "por", len: 2 }, 0xEC: { mnem: "paddsb", len: 2 }, 0xED: { mnem: "paddsw", len: 2 }, 0xEE: { mnem: "pmaxsw", len: 2 }, 0xEF: { mnem: "pxor", len: 2 },
            0xF0: { mnem: "lddqu", len: 2 },  0xF1: { mnem: "psllw", len: 2 },  0xF2: { mnem: "pslld", len: 2 },  0xF3: { mnem: "psllq", len: 2 },  0xF4: { mnem: "pmuludq", len: 2 },  0xF5: { mnem: "pmaddwd", len: 2 },  0xF6: { mnem: "psadbw", len: 2 },  0xF7: { mnem: "maskmovq", len: 2 },  0xF8: { mnem: "psubb", len: 2 },  0xF9: { mnem: "psubw", len: 2 },  0xFA: { mnem: "psubd", len: 2 },
            0xFB: { mnem: "psubq", len: 2 }, 0xFC: { mnem: "paddb", len: 2 }, 0xFD: { mnem: "paddw", len: 2 }, 0xFE: { mnem: "paddd", len: 2 }, 0xFF: { mnem: "paddq", len: 2 }
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
            
            const isZeroBlock = opcode === 0x00 && bytes[offset + 1] === 0x00 && bytes[offset + 2] === 0x00;
            const isDataPattern = (opcode >= 0x20 && opcode <= 0x7E) &&
                                  bytes[offset + 1] === 0x00 &&        
                                  (bytes[offset + 2] === 0x00 || bytes[offset + 2] === 0x20);
            
            if (isZeroBlock || isDataPattern) {
                consecutiveData++;
                if (consecutiveData > 10 && !inDataSection) {
                    inDataSection = true;
                    instructions.push({
                        rva: rva - consecutiveData * 1,
                        offset: offset - consecutiveData,
                        bytes: '...',
                        text: '// ========== DATA SECTION START ==========',
                        length: 0,
                        isDataMarker: true
                    });
                }
            } else {
                consecutiveData = 0;
                inDataSection = false;
            }
            
            if (inDataSection) {
                const nextBytes = bytes.slice(offset, offset + 16);
                const hasCodePattern = nextBytes.some(b => b === 0x55 || b === 0xE8 || b === 0xE9 || b === 0xC3);
                
                if (hasCodePattern && consecutiveData < 5) {
                    inDataSection = false;
                    instructions.push({
                        rva: rva,
                        offset: offset,
                        bytes: '...',
                        text: '// ========== CODE SECTION RESUME ==========',
                        length: 0,
                        isDataMarker: true
                    });
                } else {
                    const ascii = bytes.slice(offset, Math.min(offset + 16, bytes.length))
                        .map(b => (b >= 0x20 && b <= 0x7E) ? String.fromCharCode(b) : '.')
                        .join('');
                    instructions.push({
                        rva: rva,
                        offset: offset,
                        bytes: instBytes.slice(0, 16).join(' '),
                        text: `db ${instBytes[0]}`,
                        length: 1,
                        isData: true,
                        asciiPreview: ascii
                    });
                    offset++;
                    continue;
                }
            }
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

            if (instText === "ret" && instLength === 3 && bytes.length > offset + 2) {
                const imm = bytes[offset + 1] | (bytes[offset + 2] << 8);
                instText = `ret 0x${imm.toString(16)}`;
            }

            if (opcode === 0xE3) {
                if (this.is64bit && rexW) {
                    instText = "jrcxz";
                } else if (this.is64bit || this.is32bit) {
                    instText = "jecxz";
                } else {
                    instText = "jcxz";
                }
                const disp = bytes[offset + 1];
                instText = `${instText} 0x${(rva + 2 + (disp > 127 ? disp - 256 : disp)).toString(16)}`;
                instLength = 2;
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

    // INTEL DRIVER SETTINGS

    isIntelVP() {
        if (this.bytes[0] === 0x1A && this.bytes[1] === 0x01 && this.bytes[2] === 0x03) {
            return true;
        }
        const headerOffset = this.findMagicHeader();
        if (headerOffset !== -1) return true;
        const sample = new TextDecoder('utf-8').decode(this.bytes.slice(0, 4096));
        return sample.includes('igdkmd64') || 
               (sample.includes('IMap') && sample.includes('Relocations')) ||
               sample.includes('A_PUBLIC_KEY');
    }

    findMagicHeader() {
        for (let i = 0; i < Math.min(this.bytes.length - 3, 1024); i++) {
            if (this.bytes[i] === 0x1A && 
                this.bytes[i+1] === 0x01 && 
                this.bytes[i+2] === 0x03) {
                return i;
            }
        }
        return -1;
    }

    parseIntelVPHeader() {
        let offset = 0;
        
        if (this.bytes[0] !== 0x1A) {
            const magicOffset = this.findMagicHeader();
            if (magicOffset === -1) return null;
            offset = magicOffset;
        }
        
        if (offset + 40 > this.bytes.length) return null;
        
        try {
            const header = {
                magic: this.view.getUint8(offset),
                versionMinor: this.view.getUint8(offset+1),
                type: this.view.getUint8(offset+2),
                reserved: this.view.getUint8(offset+3),
                unknown1: this.view.getUint32(offset+7, true),
                entryCount: this.view.getUint16(offset+9, true),
                offsetA: this.view.getUint32(offset+13, true),
                offsetB: this.view.getUint32(offset+17, true),
                flags: this.view.getUint32(offset+21, true),
                nameCount: this.view.getUint16(offset+23, true),
                embeddedFiles: [],
                rawOffset: offset
            };
            
            for (let i = 0; i < header.nameCount; i++) {
                if (offset + 2 > this.bytes.length) break;
                const nameLen = this.view.getUint16(offset, true); offset += 2;
                if (offset + nameLen > this.bytes.length) break;
                
                let nameBytes = [];
                for (let j = 0; j < nameLen; j++) {
                    nameBytes.push(this.bytes[offset + j]);
                }
                offset += nameLen;
                const name = new TextDecoder('utf-8').decode(new Uint8Array(nameBytes));
                const endMarker = (offset < this.bytes.length) ? this.view.getUint8(offset) : 0;
                offset += 1;
                
                header.embeddedFiles.push({
                    name: name,
                    nameLen: nameLen,
                    endMarker: endMarker
                });
            }
            
            return header;
        } catch (e) {
            console.warn("Failed to parse Intel VP header:", e);
            return null;
        }
    }

    findEmbeddedPEFiles() {
        const embedded = [];
        let offset = 0;
        
        while ((offset = this.findMZ(offset)) !== -1) {
            if (offset + 0x40 > this.bytes.length) break;
            const e_lfanew = this.view.getUint32(offset + 0x3C, true);
            if (e_lfanew > 0 && offset + e_lfanew + 4 <= this.bytes.length) {
                const peSig = this.view.getUint32(offset + e_lfanew, true);
                if (peSig === 0x00004550) { // "PE\0\0"
                    let name = this.findPENameNear(offset);
                    
                    embedded.push({
                        offset: offset,
                        name: name || `embedded_${embedded.length}.pe`,
                        size: this.getPESize(offset),
                        e_lfanew: e_lfanew
                    });
                }
            }
            offset += 2;
        }
        
        return embedded;
    }
 
    findMZ(start = 0) {
        for (let i = start; i < this.bytes.length - 1; i++) {
            if (this.bytes[i] === 0x4D && this.bytes[i + 1] === 0x5A) {
                return i;
            }
        }
        return -1;
    }

    findPENameNear(offset) {
        const start = Math.max(0, offset - 256);
        const end = Math.min(this.bytes.length, offset + 256);
        const context = this.bytes.slice(start, end);
        const str = new TextDecoder('utf-8').decode(context);
        
        const match = str.match(/[a-zA-Z0-9_]+\.(sys|dll|exe|drv)/i);
        if (match) return match[0];
        
        if (str.includes('igdkmd64')) return 'igdkmd64.sys';
        
        return null;
    }

    getPESize(offset) {
        let nextMZ = this.findMZ(offset + 2);
        if (nextMZ !== -1 && nextMZ > offset) {
            return nextMZ - offset;
        }
        return this.bytes.length - offset;
    }

    extractVPVersion() {
        const str = new TextDecoder('utf-8').decode(this.bytes.slice(0, 4096));
        const match = str.match(/(\d+\.\d+\.\d+\.\d+)/);
        return match ? match[0] : null;
    }
    
    findVPSections() {
        const markers = ['IMap', 'Relocations', 'A_PUBLIC_KEY', 'SIGNER_ATTR'];
        const sections = [];
        
        for (const marker of markers) {
            const pos = this.findStringInBytes(marker);
            if (pos !== -1) {
                let end = this.bytes.length;
                for (const m of markers) {
                    const nextPos = this.findStringInBytes(m, pos + marker.length);
                    if (nextPos !== -1 && nextPos > pos && nextPos < end) {
                        end = nextPos;
                    }
                }
                sections.push({
                    name: marker,
                    offset: pos,
                    size: Math.min(end - pos, 65536),
                    type: 'marker'
                });
            }
        }
        
        return sections;
    }
    
    findStringInBytes(str, start = 0) {
        const target = new TextEncoder().encode(str);
        for (let i = start; i < this.bytes.length - target.length; i++) {
            let found = true;
            for (let j = 0; j < target.length; j++) {
                if (this.bytes[i + j] !== target[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }

    hasVPSignature() {
        const str = new TextDecoder('utf-8').decode(this.bytes.slice(0, 8192));
        return str.includes('A_PUBLIC_KEY') && str.includes('SIGNER_ATTR');
    }

    parseIMap(offset, size) {
        if (offset === -1 || size < 32) return null;
        
        try {
            const imap = {
                rawSize: size,
                entries: [],
                version: null,
                imageCount: 0
            };
            
            let dataOffset = offset;
            while (dataOffset < offset + size) {
                const byte = this.bytes[dataOffset];
                if (byte >= 0x20 && byte <= 0x7E) {
                    dataOffset++;
                } else {
                    break;
                }
            }
            
            while (dataOffset % 4 !== 0 && dataOffset < offset + size) {
                dataOffset++;
            }
            
            let pos = dataOffset;
            let entryIndex = 0;
            
            while (pos + 16 <= offset + size && entryIndex < 100) {
                const entry = {
                    index: entryIndex,
                    offset: pos,
                    rva: this.view.getUint32(pos, true),
                    size: this.view.getUint32(pos + 4, true),
                    flags: this.view.getUint32(pos + 8, true),
                    unknown: this.view.getUint32(pos + 12, true)
                };
                
                if (entry.rva !== 0 || entry.size !== 0) {
                    imap.entries.push(entry);
                } else {
                    if (entryIndex > 0 && entry.rva === 0 && entry.size === 0) {
                        break;
                    }
                }
                
                pos += 16;
                entryIndex++;
            }
            
            const str = new TextDecoder('utf-8').decode(this.bytes.slice(offset, Math.min(offset + 128, this.bytes.length)));
            const versionMatch = str.match(/(\d+\.\d+\.\d+\.\d+)/);
            if (versionMatch) {
                imap.version = versionMatch[1];
            }
            
            const fimapPos = this.findStringInBytes('FIMap', offset);
            if (fimapPos !== -1) {
                imap.hasFIMap = true;
                imap.fimapOffset = fimapPos;
            }
            
            imap.imageCount = imap.entries.length;
            
            return imap;
        } catch (e) {
            console.warn("Failed to parse IMap:", e);
            return null;
        }
    }

    async scanIntelVP() {
        console.log("🔍 Scanning Intel VP container...");
        const header = this.parseIntelVPHeader();
        const sections = this.findVPSections();
        const embeddedPE = this.findEmbeddedPEFiles();
        const version = this.extractVPVersion();
        const hasSignature = this.hasVPSignature();
        if (header) {
            this.result.tables.push({
                title: "Intel VP Header",
                icon: "chip",
                columns: ["Field", "Value"],
                rows: [
                    ["Magic", `0x${header.magic.toString(16)}`],
                    ["Version", `${header.versionMinor}.${header.type}`],
                    ["Entry Count", header.entryCount],
                    ["Flags", `0x${header.flags.toString(16)}`],
                    ["Embedded Files", header.embeddedFiles.map(f => f.name).join(", ") || "None"],
                    ["Name Count", header.nameCount]
                ]
            });
        }
        
        if (sections.length > 0) {
            this.result.tables.push({
                title: `📁 VP Sections (${sections.length})`,
                icon: "sections",
                columns: ["Name", "Offset", "Size", "Type"],
                rows: sections.map(s => [
                    s.name,
                    `0x${s.offset.toString(16)}`,
                    `${s.size} bytes`,
                    s.type
                ])
            });
        }

         const imapSection = sections.find(s => s.name === 'IMap');
        let imapInfo = null;
        if (imapSection) {
            imapInfo = this.parseIMap(imapSection.offset, imapSection.size);
        }
        
        if (imapInfo && imapInfo.entries.length > 0) {
            const imapRows = imapInfo.entries.slice(0, 50).map(e => [
                e.index,
                `0x${e.rva.toString(16)}`,
                `0x${e.size.toString(16)}`,
                `0x${e.flags.toString(16)}`
            ]);
            
            this.result.tables.push({
                title: `🗺️ IMap - Image Map (${imapInfo.imageCount} entries)`,
                icon: "map",
                columns: ["Index", "RVA", "Size", "Flags"],
                rows: imapRows
            });
            
            if (imapInfo.version) {
                this.result.tables.push({
                    title: `📌 IMap Info`,
                    icon: "info",
                    columns: ["Property", "Value"],
                    rows: [
                        ["Driver Version", imapInfo.version],
                        ["Has FIMap", imapInfo.hasFIMap ? "✅ Yes" : "❌ No"],
                        ["Total Images", imapInfo.imageCount]
                    ]
                });
            }
        }

        const pubKeySection = sections.find(s => s.name === 'A_PUBLIC_KEY');
        let publicKeyInfo = null;
        if (pubKeySection) {
            publicKeyInfo = this.parseIntelPublicKey(pubKeySection.offset, pubKeySection.size);
        }

        const signerSection = sections.find(s => s.name === 'SIGNER_ATTR');
        let signerInfo = null;
        if (signerSection) {
            signerInfo = this.parseSignerAttr(signerSection.offset, signerSection.size);
        }
        
        if (publicKeyInfo) {
            const keyRows = [
                ["Format", publicKeyInfo.format],
                ["Raw Size", `${publicKeyInfo.rawSize} bytes`],
                ["Header (first 16 bytes)", publicKeyInfo.headerHex || "N/A"]
            ];
            
            if (publicKeyInfo.keyType) {
                keyRows.push(["Key Type", publicKeyInfo.keyType]);
            }
            if (publicKeyInfo.keyBits) {
                keyRows.push(["Key Size", `${publicKeyInfo.keyBits} bits`]);
            }
            if (publicKeyInfo.rsaExponent) {
                keyRows.push(["Exponent", `0x${publicKeyInfo.rsaExponent.toString(16)} (65537)`]);
            }
            if (publicKeyInfo.modulusPreview) {
                keyRows.push(["Modulus Preview", publicKeyInfo.modulusPreview]);
            }
            if (publicKeyInfo.embeddedStrings && publicKeyInfo.embeddedStrings.length > 0) {
                keyRows.push(["Embedded Strings", publicKeyInfo.embeddedStrings.slice(0, 5).join(", ")]);
            }
            
            this.result.tables.push({
                title: `🔑 Intel Public Key (A_PUBLIC_KEY)`,
                icon: "key",
                columns: ["Property", "Value"],
                rows: keyRows
            });
        }
    
        if (signerInfo) {
            const attrRows = [
                ["Size", `${signerInfo.rawSize} bytes`]
            ];
            
            if (signerInfo.oids && signerInfo.oids.length > 0) {
                attrRows.push(["OIDs", signerInfo.oids.join(", ")]);
            }
            
            if (signerInfo.attributes && signerInfo.attributes.length > 0) {
                attrRows.push(["Attributes", signerInfo.attributes.slice(0, 10).join(", ")]);
                if (signerInfo.attributes.length > 10) {
                    attrRows.push(["...", `and ${signerInfo.attributes.length - 10} more`]);
                }
            }
            
            this.result.tables.push({
                title: `📜 Signer Attributes (SIGNER_ATTR)`,
                icon: "signature",
                columns: ["Property", "Value"],
                rows: attrRows
            });
        }
        
        if (embeddedPE.length > 0) {
            const peRows = embeddedPE.map(f => [
                f.name,
                `0x${f.offset.toString(16)}`,
                `${f.size} bytes`,
                f.e_lfanew ? `PE@${f.e_lfanew}` : "MZ"
            ]);
            
            this.result.tables.push({
                title: `📦 Embedded PE Files (${embeddedPE.length})`,
                icon: "archive",
                columns: ["Name", "Offset", "Size", "PE Header"],
                rows: peRows
            });
            
            const driver = embeddedPE.find(f => f.name.includes('igdkmd64') || f.name.includes('.sys'));
            if (driver) {
                this.result.tables.push({
                    title: `⚠️ Embedded Driver: ${driver.name}`,
                    icon: "warning",
                    columns: ["Info"],
                    rows: [["This VP contains a PE driver at offset 0x" + driver.offset.toString(16) + ". Use PE analyzer for deeper inspection."]]
                });
            }
        }
        
        if (version) {
            this.result.tables.push({
                title: "Driver Information",
                icon: "info",
                columns: ["Property", "Value"],
                rows: [
                    ["Driver Version", version],
                    ["Vendor", "Intel Corporation"],
                    ["Format", "Intel Graphics VP Container"]
                ]
            });
        }
        
        const metadataRows = [
            ["Format Type", "Intel Graphics VP Container"],
            ["Total Size", `${this.bytes.length} bytes`],
            ["Sections Found", sections.length],
            ["Embedded Files", embeddedPE.length],
            ["Has Digital Signature", hasSignature ? "✅ Yes" : "❌ No"],
            ["Intel Specific", "✅ Yes"]
        ];
        
        if (header) {
            metadataRows.push(["Entry Count", header.entryCount]);
            metadataRows.push(["Name Count", header.nameCount]);
        }
        
        this.result.tables.push({
            title: "Intel VP Metadata",
            icon: "intel",
            columns: ["Property", "Value"],
            rows: metadataRows
        });
        
        const strings = this.extractVPStrings();
        if (strings.length > 0) {
            const formattedRows = strings.slice(0, 200).map(s => {
                let displayValue = s.value;
                if (displayValue.length > 80) {
                    displayValue = displayValue.substring(0, 77) + '...';
                }
                displayValue = displayValue.replace(/</g, '&lt;').replace(/>/g, '&gt;');
                return [`0x${s.offset.toString(16)}`, `"${displayValue}"`];
            });
            
            this.result.tables.push({
                title: `📝 String Literals (${strings.length})`,
                icon: "string",
                columns: ["Offset", "String"],
                rows: formattedRows
            });
            
            if (strings.length > 200) {
                this.result.tables.push({
                    title: `📝 Additional Strings (${strings.length - 200} more)`,
                    icon: "string",
                    columns: ["Note"],
                    rows: [["Use Export JSON to see all " + strings.length + " strings"]]
                });
            }
        }
        
        console.log(`✅ Intel VP scan complete: ${sections.length} sections, ${embeddedPE.length} embedded PE files`);
    }

    extractVPStrings() {
        const strings = [];
        let i = 0;
        const minLen = 3;
        
        while (i < this.bytes.length) {
            while (i < this.bytes.length && (this.bytes[i] < 0x20 || this.bytes[i] > 0x7E)) {
                i++;
            }
            if (i >= this.bytes.length) break;
            
            let start = i;
            let strBytes = [];
            while (i < this.bytes.length && this.bytes[i] >= 0x20 && this.bytes[i] <= 0x7E) {
                strBytes.push(this.bytes[i]);
                i++;
            }
            
            if (strBytes.length >= minLen) {
                const str = new TextDecoder('utf-8').decode(new Uint8Array(strBytes));
                if (!str.match(/^[0-9a-f]+$/i) &&      
                    !str.match(/^[A-Za-z0-9]{16,}$/) &&
                    str.length < 128 &&                
                    !str.includes('\\') &&             
                    !str.match(/^[\.\*\+\?\[\]\{\}\(\)\|\\]+$/)) {
                    
                    let cleanStr = str.replace(/[\x00-\x1F\x7F]/g, '.');
                    
                    strings.push({
                        offset: start,
                        value: cleanStr,
                        length: strBytes.length
                    });
                }
            }
        }
        
        strings.sort((a, b) => a.offset - b.offset);
        
        return strings;
    }

    parseIntelPublicKey(offset, size) {
        if (offset === -1 || size < 16) return null;
        
        try {
            const result = {
                rawSize: size,
                format: "Intel Custom Key Blob",
                header: [],
                keyType: null,
                keyBits: null,
                rsaModulus: null,
                rsaExponent: null,
                additionalData: []
            };
            
            const headerBytes = [];
            for (let i = 0; i < Math.min(16, size); i++) {
                headerBytes.push(this.view.getUint8(offset + i).toString(16).padStart(2, '0'));
            }
            result.headerHex = headerBytes.join(' ');
            
            const rsaPatterns = [];
            for (let i = offset; i < offset + size - 4; i++) {
                const val = this.view.getUint32(i, true);
                if (val === 0x31415352) rsaPatterns.push({ type: "RSA1", pos: i });
                if (val === 0x32415352) rsaPatterns.push({ type: "RSA2", pos: i });
                if (val === 0x00010001) result.rsaExponent = 65537;
            }
            
            if (rsaPatterns.length > 0) {
                result.rsaPattern = rsaPatterns;
            }
            
            const possibleModulusStart = offset + 8;
            let modulusBytes = 0;
            for (let i = possibleModulusStart; i < offset + size - 4; i++) {
                if (this.view.getUint32(i, true) === 0x00010001) {
                    modulusBytes = i - possibleModulusStart;
                    result.rsaExponentOffset = i;
                    break;
                }
            }
            
            if (modulusBytes > 0) {
                result.keyBits = modulusBytes * 8;
                result.keyType = "RSA";
                
                const previewBytes = [];
                for (let i = 0; i < Math.min(16, modulusBytes); i++) {
                    previewBytes.push(this.view.getUint8(possibleModulusStart + i).toString(16).padStart(2, '0'));
                }
                result.modulusPreview = previewBytes.join(' ');
            }
            
            const strings = [];
            let i = offset;
            while (i < offset + size) {
                while (i < offset + size && (this.bytes[i] < 0x20 || this.bytes[i] > 0x7E)) i++;
                if (i >= offset + size) break;
                
                let strBytes = [];
                let start = i;
                while (i < offset + size && this.bytes[i] >= 0x20 && this.bytes[i] <= 0x7E) {
                    strBytes.push(this.bytes[i]);
                    i++;
                }
                if (strBytes.length >= 3) {
                    const str = new TextDecoder('utf-8').decode(new Uint8Array(strBytes));
                    if (!str.match(/^[0-9a-f]+$/i) && !str.includes('\\')) {
                        strings.push(str);
                    }
                }
            }
            
            if (strings.length > 0) {
                result.embeddedStrings = strings.slice(0, 10);
            }
            
            return result;
        } catch (e) {
            console.warn("Failed to parse Intel Public Key:", e);
            return null;
        }
    }

    parseSignerAttr(offset, size) {
        if (offset === -1 || size < 8) return null;
        
        try {
            const signerAttr = {
                rawSize: size,
                version: null,
                attributes: []
            };
            
            const str = new TextDecoder('utf-8').decode(this.bytes.slice(offset, offset + Math.min(size, 256)));
            const matches = str.match(/[a-zA-Z0-9_\-\.]{4,}/g);
            if (matches) {
                signerAttr.attributes = [...new Set(matches)].slice(0, 20);
            }
            
            const oids = [];
            const oidPatterns = [
                "1.3.6.1.4.1.311",  // Microsoft
                "1.2.840.113549",    // RSA
                "2.5.4.3"            // Common Name
            ];
            
            for (const oid of oidPatterns) {
                if (str.includes(oid)) {
                    oids.push(oid);
                }
            }
            
            if (oids.length > 0) {
                signerAttr.oids = oids;
            }
            
            return signerAttr;
        } catch (e) {
            console.warn("Failed to parse SIGNER_ATTR:", e);
            return null;
        }
    }

    findRSAData(offset, size) {
        for (let i = offset; i < offset + size - 4; i++) {
            const val = this.view.getUint32(i, true);
            if (val === 0x31415352 || val === 0x32415352) { // "RSA1" or "RSA2"
                return i;
            }
        }
        return -1;
    }

    // INTEL ONLY END

    // WINDOWS ACTIVATION LICENSE

    extractHardwareID() {
        const result = {
            found: false,
            offset: null,
            size: null,
            hex: null,
            asString: null,
            possibleFormats: []
        };
        
        const searchStart = Math.max(0, this.bytes.length - 128);
        for (let offset = searchStart; offset < this.bytes.length - 20; offset++) {
            let isCandidate = true;
            let zeroCount = 0;
            let ffCount = 0;
            
            for (let i = 0; i < 20; i++) {
                const byte = this.bytes[offset + i];
                if (byte === 0) zeroCount++;
                if (byte === 0xFF) ffCount++;
            }
            
            if (zeroCount < 5 && ffCount < 5) {
                const nextBytes = this.bytes.slice(offset + 20, offset + 52);
                let nextHasData = false;
                for (let i = 0; i < 32; i++) {
                    if (nextBytes[i] !== 0 && nextBytes[i] !== 0xFF) {
                        nextHasData = true;
                        break;
                    }
                }
                
                if (nextHasData) {
                    result.found = true;
                    result.offset = offset;
                    result.size = 20; // SHA-1
                    result.possibleFormats.push("SHA-1 (20 bytes)");
                }
            }
        }
        
        for (let offset = searchStart; offset < this.bytes.length - 32; offset++) {
            let isCandidate = true;
            let zeroCount = 0;
            let ffCount = 0;
            
            for (let i = 0; i < 32; i++) {
                const byte = this.bytes[offset + i];
                if (byte === 0) zeroCount++;
                if (byte === 0xFF) ffCount++;
            }
            
            if (zeroCount < 8 && ffCount < 8) {
                result.found = true;
                result.offset = offset;
                result.size = 32;
                result.possibleFormats.push("SHA-256 (32 bytes)");
                break;
            }
        }
        
        if (result.found && result.offset && result.size) {
            const hexBytes = [];
            const asciiBytes = [];
            for (let i = 0; i < result.size; i++) {
                const byte = this.bytes[result.offset + i];
                hexBytes.push(byte.toString(16).padStart(2, '0'));
                if (byte >= 0x20 && byte <= 0x7E) {
                    asciiBytes.push(String.fromCharCode(byte));
                } else {
                    asciiBytes.push('.');
                }
            }
            result.hex = hexBytes.join(' ');
            result.asString = asciiBytes.join('');
        }
        
        return result;
    }

    getHardwareIDDescription() {
        return {
            purpose: "Unique identifier for your computer's hardware configuration",
            generation: "Created during Windows activation based on CPU, motherboard, HDD serial numbers",
            binding: "License is bound to this ID - changing hardware may require reactivation",
            location: "Stored in Windows license files and on Microsoft activation servers"
        };
    }

    parseWindowsLicenseFile() {
        const result = {
            isValid: false,
            version: null,
            type: null,
            encryptedDataOffset: 16,
            encryptedDataSize: this.bytes.length - 16,
            hasRSASignature: false,
            hasAESData: false,
            signatureType: null,
            encryptionType: null
        };
        
        if (this.bytes.length < 16) return result;
        
        result.version = this.view.getUint32(0, true);
        result.type = this.view.getUint32(4, true);
        
        if (result.version === 5 || result.version === 6) {
            result.isValid = true;
        }
        
        const encOffset = result.encryptedDataOffset;
        const encSize = result.encryptedDataSize;
        
        if (encSize >= 256) {
            let hasNonZero = false;
            for (let i = 0; i < 256 && encOffset + i < this.bytes.length; i++) {
                if (this.bytes[encOffset + i] !== 0) {
                    hasNonZero = true;
                    break;
                }
            }
            
            if (hasNonZero) {
                result.hasRSASignature = true;
                result.signatureType = "RSA-2048";
                
                if (this.bytes[encOffset] === 0x00) {
                    result.signatureFormat = "PKCS#1 v1.5";
                } else {
                    result.signatureFormat = "Raw RSA (likely encrypted with private key)";
                }
            }
        }
        
        if (encSize > 256) {
            const aesStart = encOffset + 256;
            let hasRandom = false;
            let zeroCount = 0;
            for (let i = 0; i < Math.min(64, encSize - 256); i++) {
                if (this.bytes[aesStart + i] === 0) zeroCount++;
            }
            if (zeroCount < 6) {
                result.hasAESData = true;
                result.encryptionType = "AES-128-CBC or AES-256-CBC";
            }
        }
        
        const lastBytes = this.bytes.slice(Math.max(0, this.bytes.length - 64), this.bytes.length);
        
        let sha1Candidate = null;
        for (let i = 0; i <= lastBytes.length - 20; i++) {
            let isSha1 = true;
            let hasNonFF = false;
            for (let j = 0; j < 20; j++) {
                if (lastBytes[i + j] === 0xFF) isSha1 = false;
                if (lastBytes[i + j] !== 0) hasNonFF = true;
            }
            if (isSha1 && hasNonFF) {
                sha1Candidate = i;
                break;
            }
        }
        
        if (sha1Candidate !== null) {
            result.hasHardwareID = true;
            result.hardwareIDOffset = this.bytes.length - (lastBytes.length - sha1Candidate);
        }
        
        return result;
    }

    analyzeAESData(offset, size) {
        const result = {
            isValid: false,
            iv: null,
            encryptedData: null,
            hmac: null,
            possiblePadding: null,
            dataStructure: null
        };
        
        if (size < 48) return result;
        
        const potentialIV = [];
        for (let i = 0; i < 16 && offset + i < this.bytes.length; i++) {
            potentialIV.push(this.view.getUint8(offset + i).toString(16).padStart(2, '0'));
        }
        result.iv = potentialIV.join(' ');
        
        const encryptedSize = size - 16;
        result.encryptedData = {
            offset: offset + 16,
            size: encryptedSize,
            hexPreview: []
        };
        
        for (let i = 0; i < Math.min(32, encryptedSize); i++) {
            result.encryptedData.hexPreview.push(
                this.view.getUint8(offset + 16 + i).toString(16).padStart(2, '0')
            );
        }
        
        if (encryptedSize > 32) {
            const hmacStart = offset + 16 + encryptedSize - 32;
            const hmacBytes = [];
            for (let i = 0; i < 32; i++) {
                hmacBytes.push(this.view.getUint8(hmacStart + i).toString(16).padStart(2, '0'));
            }
            result.hmac = hmacBytes.join(' ');
            result.encryptedData.sizeWithoutHMAC = encryptedSize - 32;
        }
        
        if (encryptedSize % 16 === 0) {
            result.possiblePadding = "PKCS#7 (16-byte blocks)";
            result.isValid = true;
        }
        
        const firstBytes = this.bytes.slice(offset + 16, offset + 16 + 16);
        let entropy = 0;
        const freq = {};
        for (let i = 0; i < firstBytes.length; i++) {
            const b = firstBytes[i];
            freq[b] = (freq[b] || 0) + 1;
        }
        for (const count of Object.values(freq)) {
            const p = count / firstBytes.length;
            entropy -= p * Math.log2(p);
        }
        
        if (entropy > 7.5) {
            result.dataStructure = "High entropy - likely encrypted or compressed";
        } else {
            result.dataStructure = "Low entropy - possibly plaintext or simple encoding";
        }
        
        return result;
    }
    
    async scanWindowsLicense() {
        const header = this.parseWindowsLicenseFile();
        
        const rows = [
            ["File Name", this.options.fileName || "Unknown"],
            ["File Size", `${this.bytes.length} bytes`],
            ["Format", "Windows Software Licensing (SLP)"],
            ["Header Version", header.version === 5 ? "Windows 7 / Server 2008 R2" : 
                              header.version === 6 ? "Windows 8/10/11" : `Unknown (${header.version})`],
            ["Header Type", header.type === 0 ? "Backup / Secondary Copy" : "Primary Activation Data"],
            ["Encrypted Data Offset", `0x${header.encryptedDataOffset.toString(16)}`],
            ["Encrypted Data Size", `${header.encryptedDataSize} bytes`]
        ];
        
        if (header.hasRSASignature) {
            rows.push(["RSA Signature", `✅ Present (${header.signatureType})`]);
            rows.push(["Signature Format", header.signatureFormat || "Unknown"]);
        } else {
            rows.push(["RSA Signature", "❌ Not detected"]);
        }
        
        // Encryption info
        if (header.hasAESData) {
            rows.push(["AES Encrypted Data", `✅ Present (${header.encryptionType})`]);
        }
        
        if (header.hasHardwareID) {
            rows.push(["Hardware ID", `Found at offset 0x${header.hardwareIDOffset.toString(16)}`]);
        }
        
        this.result.tables.push({
            title: "🔐 Windows License File Analysis",
            icon: "license",
            columns: ["Property", "Value"],
            rows: rows
        });
    
        const encOffset = header.encryptedDataOffset;
        
        if (header.hasRSASignature && this.bytes.length > encOffset + 32) {
            const sigPreview = [];
            for (let i = 0; i < 32; i++) {
                sigPreview.push(this.view.getUint8(encOffset + i).toString(16).padStart(2, '0'));
            }
            this.result.tables.push({
                title: "🔑 RSA Signature (first 32 bytes)",
                icon: "key",
                columns: ["Hex Dump"],
                rows: [[sigPreview.join(' ')]]
            });
        }
        
        if (header.hasAESData && this.bytes.length > encOffset + 256 + 32) {
            const aesPreview = [];
            for (let i = 0; i < 32; i++) {
                aesPreview.push(this.view.getUint8(encOffset + 256 + i).toString(16).padStart(2, '0'));
            }
            this.result.tables.push({
                title: "🔒 AES Encrypted Data (first 32 bytes)",
                icon: "lock",
                columns: ["Hex Dump"],
                rows: [[aesPreview.join(' ')]]
            });
        }

        const hid = this.extractHardwareID();
        
        if (hid.found) {
            const hidRows = [
                ["Hardware ID Format", hid.possibleFormats.join(" or ")],
                ["Offset", `0x${hid.offset.toString(16)}`],
                ["Size", `${hid.size} bytes`],
                ["HEX", hid.hex],
                ["ASCII Preview", hid.asString || "Non-printable"]
            ];
            
            this.result.tables.push({
                title: "🖥️ Hardware ID (HID) - Machine Binding",
                icon: "computer",
                columns: ["Property", "Value"],
                rows: hidRows
            });
            
            const hidDesc = this.getHardwareIDDescription();
            this.result.tables.push({
                title: "ℹ️ About Hardware ID",
                icon: "info",
                columns: ["Property", "Value"],
                rows: [
                    ["Purpose", hidDesc.purpose],
                    ["Generation", hidDesc.generation],
                    ["License Binding", hidDesc.binding],
                    ["Storage", hidDesc.location]
                ]
            });
        } else {
            this.result.tables.push({
                title: "🖥️ Hardware ID",
                icon: "computer",
                columns: ["Status"],
                rows: [["❌ Not found or encrypted in this file"]]
            });
        }
        
        this.result.tables.push({
            title: "📊 Technical Summary",
            icon: "stats",
            columns: ["Property", "Value"],
            rows: [
                ["Encryption Chain", "RSA-2048 → AES-128 → License Data"],
                ["Purpose", "Hardware-bound license verification"],
                ["Security Level", "High (Microsoft Private Key required)"],
                ["Decryption", "Only possible with Microsoft's private key or sppsvc.exe"],
                ["Integrity", "Signed by Microsoft during activation"]
            ]
        });

        if (header.hasAESData && header.encryptedDataOffset) {
            const aesOffset = header.encryptedDataOffset + 256;
            const aesSize = header.encryptedDataSize - 256;
            
            if (aesSize > 0) {
                const aesAnalysis = this.analyzeAESData(aesOffset, aesSize);
                
                const aesRows = [
                    ["Encryption Algorithm", aesAnalysis.isValid ? "AES-128-CBC or AES-256-CBC" : "Unknown"],
                    ["IV (Initialization Vector)", aesAnalysis.iv || "N/A"],
                    ["IV Size", "16 bytes"],
                    ["Encrypted Data Offset", `0x${aesAnalysis.encryptedData?.offset?.toString(16) || 'N/A'}`],
                    ["Encrypted Data Size", `${aesAnalysis.encryptedData?.size || 0} bytes`],
                    ["Block Alignment", aesAnalysis.possiblePadding || "Not aligned"],
                    ["Data Structure", aesAnalysis.dataStructure || "Unknown"]
                ];
                
                if (aesAnalysis.hmac) {
                    aesRows.push(["HMAC (last 32 bytes)", aesAnalysis.hmac]);
                    aesRows.push(["Data without HMAC", `${aesAnalysis.encryptedData?.sizeWithoutHMAC || 0} bytes`]);
                }

                if (aesAnalysis.encryptedData?.hexPreview) {
                    aesRows.push(["Encrypted Data Preview (first 32 bytes)", aesAnalysis.encryptedData.hexPreview.join(' ')]);
                }
                
                this.result.tables.push({
                    title: "🔒 AES Encrypted Data Analysis",
                    icon: "lock",
                    columns: ["Property", "Value"],
                    rows: aesRows
                });
                
                this.result.tables.push({
                    title: "📦 What's Inside AES Data (Encrypted)",
                    icon: "archive",
                    columns: ["Component", "Description", "Status"],
                    rows: [
                        ["Product Key", "Windows product key (encrypted)", "🔒 Encrypted"],
                        ["Digital License", "Digital entitlement token", "🔒 Encrypted"],
                        ["Activation ID", "Unique activation identifier", "🔒 Encrypted"],
                        ["Timestamp", "Activation date and time", "🔒 Encrypted"],
                        ["Hardware Hash", "Hardware ID confirmation", "✅ Verified separately"]
                    ]
                });
            }
        }
        
        this.result.summary = {
            fileName: this.options.fileName || "Unknown",
            type: "Windows Software Licensing",
            version: header.version,
            hasSignature: header.hasRSASignature,
            size: this.bytes.length
        };
    }
    
    getLicenseTypeName(type) {
        const types = {
            1: "Retail / OEM Activation",
            2: "Volume License (KMS/MAK)",
            3: "Evaluation / Trial",
            4: "Windows Anytime Upgrade",
            5: "Digital License"
        };
        return types[type] || `Unknown (${type})`;
    }
    
    // WL END
    
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

class ASTNode {
    constructor(type, value = null, left = null, right = null) {
        this.type = type;  // 'reg', 'const', 'add', 'sub', 'xor', 'and', 'or', 'mem', 'call'
        this.value = value; // for 'const' or 'reg' — name
        this.left = left;   // for bin ops
        this.right = right;
        this.args = [];     // for 'call'
        this.offset = 0;    // for 'mem'
        this.base = null;   // for 'mem'
        this.index = null;  // for 'mem'
        this.scale = 1;     // for 'mem'
    }
    
    toString() {
        switch(this.type) {
            case 'reg': return this.value;
            case 'const': return this.value.toString();
            case 'add': return `(${this.left.toString()} + ${this.right.toString()})`;
            case 'sub': return `(${this.left.toString()} - ${this.right.toString()})`;
            case 'xor': return `(${this.left.toString()} ^ ${this.right.toString()})`;
            case 'and': return `(${this.left.toString()} & ${this.right.toString()})`;
            case 'or':  return `(${this.left.toString()} | ${this.right.toString()})`;
            case 'mem': {
                if (this.base && this.index) {
                    return `[${this.base.toString()} + ${this.index.toString()}*${this.scale} + ${this.offset}]`;
                } else if (this.base) {
                    if (this.offset === 0) return `[${this.base.toString()}]`;
                    return `[${this.base.toString()}+0x${this.offset.toString(16)}]`;
                }
                return `[0x${this.offset.toString(16)}]`;
            }
            case 'call': return `${this.value}(${this.args.map(a => a.toString()).join(', ')})`;
            default: return '???';
        }
    }
    
    simplify() {
        if (this.left) this.left = this.left.simplify();
        if (this.right) this.right = this.right.simplify();

        if (this.type === 'mem') {
            if (this.base) this.base = this.base.simplify();
            if (this.index) this.index = this.index.simplify();
            
            if (this.base?.type === 'add') {
                let offset = 0;
                let base = null;
                
                function collect(node) {
                    if (node.type === 'add') {
                        collect(node.left);
                        collect(node.right);
                    } else if (node.type === 'const') {
                        offset += node.value;
                    } else {
                        base = node;
                    }
                }
                collect(this.base);
                
                if (base) {
                    this.base = base;
                    this.offset += offset;
                }
                return this;
            }
        }
        
        if (this.type === 'add') {
            let sum = 0;
            let terms = [];
            
            function collect(node) {
                if (node.type === 'add') {
                    collect(node.left);
                    collect(node.right);
                } else if (node.type === 'const') {
                    sum += node.value;
                } else {
                    terms.push(node);
                }
            }
            collect(this);
            
            if (terms.length === 0) {
                return new ASTNode('const', sum);
            }
            if (sum !== 0) {
                terms.push(new ASTNode('const', sum));
            }
            
            let result = terms[0];
            for (let i = 1; i < terms.length; i++) {
                result = new ASTNode('add', null, result, terms[i]);
            }
            return result;
        }
        
        switch(this.type) {
            case 'add':
                if (this.right?.type === 'const' && this.right.value === 0) return this.left;
                if (this.left?.type === 'const' && this.left.value === 0) return this.right;
                if (this.left?.type === 'const' && this.right?.type === 'const') {
                    return new ASTNode('const', this.left.value + this.right.value);
                }
                break;
                
            case 'sub':
                // x - 0 → x
                if (this.right?.type === 'const' && this.right.value === 0) return this.left;
                // x - x → 0
                if (this.left?.toString() === this.right?.toString()) {
                    return new ASTNode('const', 0);
                }
                // const - const → const
                if (this.left?.type === 'const' && this.right?.type === 'const') {
                    return new ASTNode('const', this.left.value - this.right.value);
                }
                break;
                
            case 'xor':
                if (this.left?.type === 'const' && this.left.value === 0) return this.right;
                if (this.right?.type === 'const' && this.right.value === 0) return this.left;
                if (this.left?.toString() === this.right?.toString()) return new ASTNode('const', 0);
                break;
                
            case 'and':
                // x & 0 → 0
                if (this.right?.type === 'const' && this.right.value === 0) return new ASTNode('const', 0);
                // x & -1 → x (for 32-біт)
                if (this.right?.type === 'const' && this.right.value === 0xFFFFFFFF) return this.left;
                break;
                
            case 'or':
                // x | 0 → x
                if (this.right?.type === 'const' && this.right.value === 0) return this.left;
                break;
        }
        return this;
    }
    
    clone() {
        const node = new ASTNode(this.type, this.value);
        if (this.left) node.left = this.left.clone();
        if (this.right) node.right = this.right.clone();
        node.args = this.args.map(a => a.clone());
        node.offset = this.offset;
        node.base = this.base?.clone();
        node.index = this.index?.clone();
        node.scale = this.scale;
        return node;
    }
}

class CppDecompiler {
    constructor(binaryBuffer, instructions, imports = [], strings = [], sections = []) {
        console.log("=== CppDecompiler Constructor ===");
        console.log("Instructions count:", instructions?.length || 0);
        console.log("Imports count:", imports?.length || 0);
        console.log("Strings count:", strings?.length || 0);
        
        this.buffer = binaryBuffer;
        this.sections = sections;
        
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

        function detectStruct(accesses) {
            const offsets = accesses.map(a => a.offset).sort((a,b) => a-b);
            if (offsets.length < 2) return null;
            
            const gaps = [];
            for (let i = 1; i < offsets.length; i++) {
                gaps.push(offsets[i] - offsets[i-1]);
            }
            
            const commonSize = gaps.every(g => g % 4 === 0) ? 4 : 
                               gaps.every(g => g % 8 === 0) ? 8 : 0;
            
            if (commonSize) {
                const fieldCount = Math.max(...offsets) / commonSize + 1;
                return {
                    type: 'struct',
                    baseSize: commonSize,
                    fieldCount: fieldCount,
                    offsets: offsets
                };
            }
            return null;
        }

        function generateStruct(structInfo, structName) {
            const lines = [];
            lines.push(`struct ${structName} {`);
            for (let i = 0; i <= structInfo.fieldCount; i++) {
                const offset = i * structInfo.baseSize;
                if (structInfo.offsets.includes(offset)) {
                    lines.push(`    DWORD field_0x${offset.toString(16)};  // used`);
                } else {
                    lines.push(`    DWORD padding_0x${offset.toString(16)};  // unknown`);
                }
            }
            lines.push('};');
            return lines;
        }

        const structs = new Map();

        for (const func of this.functions) {
            if (func.memAccesses) {
                for (const [baseReg, accesses] of Object.entries(func.memAccesses)) {
                    const structInfo = detectStruct(accesses);
                    if (structInfo) {
                        const structName = `struct_${baseReg}`;
                        if (!structs.has(structName)) {
                            structs.set(structName, structInfo);
                        }
                    }
                }
            }
        }

        if (structs.size > 0) {
            this.cppLines.unshift('// Detected structures:');
            for (const [name, info] of structs) {
                this.cppLines.unshift(...generateStruct(info, name));
            }
            this.cppLines.unshift('');
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

    async processFunctionAsync(func) {
        return new Promise((resolve) => {
            setTimeout(() => {
                this.processFunction(func);
                resolve();
            }, 0);
        });
    }

    buildFunctionMap() {
        if (!this.instructions || this.instructions.length === 0) {
            console.log("No instructions to build function map");
            return;
        }
        
        let currentFunc = null;
        let stats = {
            std: 0, std32: 0, fpo: 0, fpo32: 0, hotpatch: 0, 
            naked: 0, fastcall: 0, tailcall: 0, thunk: 0, unknown: 0
        };
        
        // Розширена таблиця прологів з вагою та умовами
        const prologues = [
            { pattern: [0x55, 0x48, 0x8B, 0xEC], type: 'std', weight: 100, name: 'std_x64' },
            { pattern: [0x55, 0x89, 0xE5], type: 'std32', weight: 100, name: 'std_x86' },
            { pattern: [0x55, 0x8B, 0xEC], type: 'std32', weight: 95, name: 'std_x86_alt' },
            { pattern: [0x8B, 0xFF, 0x55], type: 'hotpatch', weight: 90, name: 'hotpatch' },
            { pattern: [0xCC, 0xCC, 0x55], type: 'hotpatch', weight: 85, name: 'hotpatch_int3' },
            { pattern: [0x48, 0x83, 0xEC], type: 'fpo', weight: 80, name: 'fpo_sub_rsp' },
            { pattern: [0x48, 0x81, 0xEC], type: 'fpo', weight: 80, name: 'fpo_sub_rsp_large' },
            { pattern: [0x53, 0x56, 0x57], type: 'fpo', weight: 75, name: 'fpo_push_multi' },
            { pattern: [0x48, 0x89, 0x5C, 0x24], type: 'fpo', weight: 70, name: 'fpo_mov_rsp' },
            { pattern: [0x48, 0x8B, 0xC4], type: 'fastcall', weight: 65, name: 'fastcall' },
            { pattern: [0x40, 0x53], type: 'fpo', weight: 60, name: 'fpo_push_rbx' },
            { pattern: [0x57, 0x48, 0x83, 0xEC], type: 'fpo', weight: 75, name: 'fpo_push_rdi_sub' },
            { pattern: [0x48, 0x89, 0x5C, 0x24, 0x08], type: 'fpo', weight: 70, name: 'fpo_mov_rsp_offset' },
            { pattern: [0x83, 0xEC], type: 'fpo32', weight: 80, name: 'fpo32_sub_esp' },
            { pattern: [0x81, 0xEC], type: 'fpo32', weight: 80, name: 'fpo32_sub_esp_large' },
            { pattern: [0x53, 0x56, 0x57], type: 'fpo32', weight: 75, name: 'fpo32_push_multi' },
            { pattern: [0xFF, 0x25], type: 'thunk', weight: 95, name: 'jmp_thunk' },  // jmp [rip+...]
            { pattern: [0xE9], type: 'thunk', weight: 90, name: 'jmp_rel_thunk' },    // jmp rel32
        ];
        
        const matchPattern = (bytes, pattern) => {
            if (!bytes || pattern.length > bytes.length) return false;
            for (let j = 0; j < pattern.length; j++) {
                if (bytes[j] !== pattern[j]) return false;
            }
            return true;
        };
        
        const isCodeInstruction = (inst) => {
            const codeMnemonics = ['push', 'pop', 'mov', 'add', 'sub', 'xor', 'and', 'or', 
                                    'call', 'jmp', 'ret', 'cmp', 'test', 'lea', 'inc', 'dec',
                                    'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge'];
            
            if (codeMnemonics.includes(inst.mnemonic)) return true;
            
            if (inst.mnemonic === 'db' || inst.mnemonic === '???') {
                const bytes = inst.bytes?.split(' ').map(b => parseInt(b, 16)) || [];
                if (bytes.every(b => b === 0 || b === 0xCC || b === 0x90)) return false;
                if (bytes.length === 4 && bytes.every(b => b >= 0x20 && b <= 0x7E)) return false;
                return bytes.length <= 2;
            }
            
            return true;
        };
        
        const findFunctionEnd = (startIndex) => {
            let i = startIndex;
            let depth = 0;
            let lastRet = -1;
            
            while (i < this.instructions.length) {
                const inst = this.instructions[i];
                if (!inst) break;
                
                if (inst.mnemonic === 'call') depth++;
                if (inst.mnemonic === 'ret') {
                    if (depth === 0) {
                        lastRet = i;
                        break;
                    }
                    depth--;
                }
                
                if (i - startIndex > 10000) break;
                
                i++;
            }
            
            return lastRet !== -1 ? lastRet : i;
        };
        
        const functionStarts = [];
        const processedAddresses = new Set();
        
        for (let i = 0; i < this.instructions.length; i++) {
            const inst = this.instructions[i];
            if (!inst || processedAddresses.has(inst.rva)) continue;
            
            if (!isCodeInstruction(inst)) {
                console.log(`  Skipping non-code at 0x${inst.rva.toString(16)}: ${inst.text}`);
                continue;
            }
            
            let matchedType = null;
            let matchedName = null;
            let bestWeight = 0;
            
            const bytesArray = inst.bytes?.split(' ').map(b => parseInt(b, 16)) || [];
            for (const prologue of prologues) {
                if (matchPattern(bytesArray, prologue.pattern)) {
                    if (prologue.weight > bestWeight) {
                        bestWeight = prologue.weight;
                        matchedType = prologue.type;
                        matchedName = prologue.name;
                    }
                }
            }
            
            if (matchedType) {
                functionStarts.push({
                    index: i,
                    rva: inst.rva,
                    type: matchedType,
                    pattern: matchedName,
                    weight: bestWeight
                });
                processedAddresses.add(inst.rva);
                console.log(`  Found function start at 0x${inst.rva.toString(16)}: ${matchedType} (${matchedName})`);
            }
            else {
                const prev = this.instructions[i - 1];
                if (prev && (prev.mnemonic === 'ret' || 
                            (prev.mnemonic === 'jmp' && !prev.text.includes('call')))) {
                    functionStarts.push({
                        index: i,
                        rva: inst.rva,
                        type: 'naked',
                        pattern: 'after_ret',
                        weight: 50
                    });
                    processedAddresses.add(inst.rva);
                    console.log(`  Found naked function at 0x${inst.rva.toString(16)} (after ret/jmp)`);
                }
                else if (i === 0 || (inst.offset === 0 && inst.rva < 0x2000)) {
                    functionStarts.push({
                        index: i,
                        rva: inst.rva,
                        type: 'entry',
                        pattern: 'section_start',
                        weight: 60
                    });
                    processedAddresses.add(inst.rva);
                    console.log(`  Found entry point at 0x${inst.rva.toString(16)} (section start)`);
                }
            }
        }
        
        functionStarts.sort((a, b) => a.rva - b.rva);
        
        for (let idx = 0; idx < functionStarts.length; idx++) {
            const start = functionStarts[idx];
            const endIdx = idx + 1 < functionStarts.length ? functionStarts[idx + 1].index : this.instructions.length;
            
            const funcInsts = [];
            let hasValidCode = false;
            
            for (let i = start.index; i < endIdx && i < this.instructions.length; i++) {
                const inst = this.instructions[i];
                if (inst && isCodeInstruction(inst)) {
                    funcInsts.push(inst);
                    if (inst.mnemonic !== 'db' && inst.mnemonic !== '???') {
                        hasValidCode = true;
                    }
                }
            }
            
            if (!hasValidCode && funcInsts.length < 3) {
                console.log(`  Skipping empty function at 0x${start.rva.toString(16)}`);
                continue;
            }
            
            let savedRegs = [];
            if (start.type === 'fpo' || start.type === 'fpo32') {
                savedRegs = this.analyzeSavedRegisters(funcInsts);
            }
            
            let funcName = null;
            if (this.symbols && this.symbols.has(start.rva)) {
                funcName = this.symbols.get(start.rva);
            } else {
                funcName = `${start.type}_func_0x${start.rva.toString(16)}`;
            }
            
            const func = {
                name: funcName,
                start: start.rva,
                startIndex: start.index,
                endIndex: endIdx - 1,
                insts: funcInsts,
                type: start.type,
                pattern: start.pattern,
                savedRegs: savedRegs,
                hasRet: funcInsts.some(inst => inst.mnemonic === 'ret'),
                hasCall: funcInsts.some(inst => inst.mnemonic === 'call'),
                size: funcInsts.length,
                weight: start.weight
            };
            
            this.functions.push(func);
            stats[start.type] = (stats[start.type] || 0) + 1;
            
            console.log(`  Created function: ${func.name} (${func.type}, ${func.insts.length} instr, weight:${func.weight})`);
        }
        
        for (let i = 0; i < this.functions.length; i++) {
            const func = this.functions[i];
            const lastInst = func.insts[func.insts.length - 1];
            
            if (lastInst && lastInst.mnemonic === 'jmp' && !lastInst.text.includes('call')) {
                const target = this.extractJumpTarget(lastInst.text);
                if (target) {
                    const targetFunc = this.functions.find(f => f.start === target);
                    if (targetFunc) {
                        func.tailCall = targetFunc.name;
                        func.type = 'tailcall';
                        stats.tailcall++;
                    }
                }
            }
            
            if (func.insts.length === 1 && (lastInst.mnemonic === 'jmp' || lastInst.mnemonic === 'call')) {
                func.type = 'thunk';
                stats.thunk++;
            }
            
            func.usedArgs = this.analyzeArgUsage(func.insts);
            func.stackFrame = this.analyzeStackFrame(func.insts, func.type);
        }
        
        console.log(`\n📊 Function Map Statistics:`);
        console.log(`   Total functions: ${this.functions.length}`);
        console.log(`   ├── std (x64): ${stats.std || 0}`);
        console.log(`   ├── std32 (x86): ${stats.std32 || 0}`);
        console.log(`   ├── FPO (x64): ${stats.fpo || 0}`);
        console.log(`   ├── FPO32 (x86): ${stats.fpo32 || 0}`);
        console.log(`   ├── hotpatch: ${stats.hotpatch || 0}`);
        console.log(`   ├── naked: ${stats.naked || 0}`);
        console.log(`   ├── fastcall: ${stats.fastcall || 0}`);
        console.log(`   ├── tailcall: ${stats.tailcall || 0}`);
        console.log(`   ├── thunk: ${stats.thunk || 0}`);
        console.log(`   └── entry: ${stats.entry || 0}`);
        
        if (stats.fpo > 0) {
            console.log(`\n⚠️  Warning: ${stats.fpo} FPO functions detected. These may not decompile correctly.`);
            console.log(`   Consider using FPODeoptimizer for better results.`);
        }
        
        if (stats.naked > 0) {
            console.log(`\n⚠️  Warning: ${stats.naked} naked functions detected. These lack prolog/epilog.`);
        }
        
        return this.functions;
    }
    
    analyzeSavedRegisters(instructions) {
        const savedRegs = [];
        const regOrder = ['rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'];
        
        for (const inst of instructions) {
            if (inst.mnemonic === 'push') {
                for (const reg of regOrder) {
                    if (inst.text.includes(reg) && !savedRegs.includes(reg)) {
                        savedRegs.push(reg);
                        break;
                    }
                }
            }
            
            // mov [rsp+...], reg
            const movMatch = inst.text.match(/mov\s+\[rsp\+0x([0-9a-f]+)\],\s+(r[a-z0-9]+)/i);
            if (movMatch) {
                const reg = movMatch[2];
                if (!savedRegs.includes(reg) && regOrder.includes(reg)) {
                    savedRegs.push(reg);
                }
            }
        }
        
        return savedRegs;
    }
    
    analyzeArgUsage(instructions) {
        const used = { rcx: false, rdx: false, r8: false, r9: false, stack: [] };
        const regPattern = /\b(rcx|rdx|r8|r9)\b/gi;
        
        for (const inst of instructions) {
            let match;
            while ((match = regPattern.exec(inst.text)) !== null) {
                used[match[1]] = true;
            }
            const stackMatch = inst.text.match(/\[rsp\+0x([0-9a-f]+)\]/i);
            if (stackMatch) {
                const offset = parseInt(stackMatch[1], 16);
                used.stack.push(offset);
            }
        }
        
        return used;
    }
    
    analyzeStackFrame(instructions, funcType) {
        const frame = {
            size: 0,
            savedRegsSize: 0,
            localsSize: 0,
            hasFramePointer: funcType === 'std' || funcType === 'std32',
            usesRbp: false
        };
        
        for (const inst of instructions) {
            const subMatch = inst.text.match(/sub\s+rsp,\s*(0x[0-9a-f]+|\d+)/i);
            if (subMatch) {
                const size = parseInt(subMatch[1], 16);
                frame.size += size;
            }
            
            if (inst.text.includes('rbp') || inst.text.includes('ebp')) {
                frame.usesRbp = true;
            }
        }
        
        frame.localsSize = frame.size - frame.savedRegsSize;
        return frame;
    }
    
    extractJumpTarget(text) {
        const match = text.match(/0x([0-9a-f]+)/i);
        return match ? parseInt(match[1], 16) : null;
    }

    buildAddressMap() {
        this.functionNames = new Map();
        this.apiNames = new Map();     
        this.dllNames = new Set();     
        
        for (const str of this.strings) {
            const addr = str.address;
            const value = str.value;
            
            if (value.endsWith('.pdb')) continue;
            
            if (value.toLowerCase().endsWith('.dll')) {
                this.dllNames.add(value);
                continue;
            }
            
            if (/^[A-Z][a-zA-Z0-9_]+$/.test(value)) {
                if (addr >= 0x1000 && addr <= 0x2000) {
                    this.functionNames.set(addr, value);
                    console.log(`📌 Function at 0x${addr.toString(16)}: ${value}`);
                } 
                else {
                    this.apiNames.set(addr, value);
                    console.log(`🔧 API at 0x${addr.toString(16)}: ${value}`);
                }
            }
        }
        
        console.log(`Found ${this.functionNames.size} function names, ${this.apiNames.size} API names`);
    }
    
    extractRegName(text) {
        const match = text.match(/push (r[a-z]+)/i);
        return match ? match[1] : null;
    }

    processFunction(func) {
        console.log(`\n${'='.repeat(60)}`);
        console.log(`  Processing ${func.name} (${func.type}, ${func.insts?.length} instructions)`);
        console.log(`${'='.repeat(60)}`);
        
        this.buildAddressMap();
        const core = new PCPU_Core(this.buffer, this.sections, this.functionNames, this.apiNames);
        
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
        
        let usesRcx = false;
        let usesRdx = false;
        let usesR8 = false;
        let usesR9 = false;
        let hasCall = false;
        
        for (const inst of func.insts) {
            if (inst.text.includes('rcx')) usesRcx = true;
            if (inst.text.includes('rdx')) usesRdx = true;
            if (inst.text.includes('r8')) usesR8 = true;
            if (inst.text.includes('r9')) usesR9 = true;
            if (inst.mnemonic === 'call') hasCall = true;
        }
        
        let functionSignature = `void ${func.name}(`;
        const args = [];
        
        if (usesRcx) args.push('int64_t arg_rcx');
        if (usesRdx) args.push('int64_t arg_rdx');
        if (usesR8) args.push('int64_t arg_r8');
        if (usesR9) args.push('int64_t arg_r9');
        
        if (args.length === 0) {
            functionSignature = `void ${func.name}(void)`;
        } else {
            functionSignature = `void ${func.name}(${args.join(', ')})`;
        }
        
        if (func.name.includes('10a1') && usesRcx && usesRdx) {
            functionSignature = `BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)`;
        } else if (func.name.includes('115d') && usesRcx && usesRdx) {
            functionSignature = `HRESULT DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)`;
        } else if (func.name.includes('1204') && usesRcx) {
            functionSignature = `STDAPI DllRegisterServer(void)`;
        } else if (!hasCall && usesRcx && !usesRdx) {
            functionSignature = `void ${func.name}(void* this_ptr)`;
        }

        const knownFunctions = {
            'W32Init': { args: [], ret: 'BOOL' },
            'W32Dispatch': { args: ['DWORD', 'DWORD', 'DWORD'], ret: 'DWORD' },
            'WOW32ResolveHandle': { args: ['HANDLE'], ret: 'HANDLE' },
            'WOW32ResolveMemory': { args: ['LPVOID', 'SIZE_T'], ret: 'LPVOID' },
            'CopyDropFilesFrom16': { args: ['HDROP', 'UINT'], ret: 'BOOL' },
            'GetCommHandle': { args: ['DWORD'], ret: 'HANDLE' },
            'GetCommShadowMSR': { args: ['DWORD', 'PDWORD'], ret: 'BOOL' }
        };
        
        if (knownFunctions[func.name]) {
            const sig = knownFunctions[func.name];
            const argsStr = sig.args.map((arg, i) => `${arg} arg${i}`).join(', ');
            functionSignature = `${sig.ret} WINAPI ${func.name}(${argsStr})`;
        }

        function detectVTable(accesses, baseReg) {
            for (const access of accesses) {
                if (access.offset === 0 && access.size === 8 && access.type === 'mov') {
                    const vtableAccess = accesses.find(a => a.offset === 0 && a.type === 'read');
                    if (vtableAccess) {
                        return true;
                    }
                }
            }
            return false;
        }
        
        this.cppLines.push(functionSignature + ' {');
        
        let localVars = new Set();
        let bodyLines = [];
        let instructionCount = 0;
        let generatedStatements = 0;
    
        console.log(`\n  📝 Processing instructions:`);
        console.log(`  ${'-'.repeat(50)}`);
    
        let localVarCounter = 0;
        const localVarMap = new Map();
    
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
                    
                    statement = statement.replace(/\barg_1\b/g, 'arg_rcx');
                    statement = statement.replace(/\barg_2\b/g, 'arg_rdx');
                    
                    const rbpMatch = statement.match(/\[rbp-0x([0-9a-f]+)\]/i);
                    if (rbpMatch) {
                        const offset = rbpMatch[1];
                        if (!localVarMap.has(offset)) {
                            localVarMap.set(offset, `local_${++localVarCounter}`);
                            localVars.add(`    int64_t local_${localVarCounter};  // [rbp-0x${offset}]`);
                        }
                        statement = statement.replace(rbpMatch[0], localVarMap.get(offset));
                    }
    
                    bodyLines.push(`    ${statement}`);
                    stepStatements.push(statement);
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

                if (inst.mnemonic === 'mov' && inst.text.includes('[rcx]') && 
                    inst.text.includes('0x') && !inst.text.includes('rbp')) {
                    const vtableMatch = inst.text.match(/mov\s+\[rcx\],\s+0x([0-9a-f]+)/i);
                    if (vtableMatch) {
                        const vtableRVA = parseInt(vtableMatch[1], 16);
                        const className = `Class_0x${vtableRVA.toString(16)}`;

                        if (func.name.includes('func_') && !hasCall) {
                            this.cppLines.unshift(`// Constructor for ${className}`);
                            functionSignature = functionSignature.replace(
                                'void* this_ptr',
                                `${className}* this`
                            );
                        }

                        bodyLines.unshift(`    this->vptr = (${className}::VTable*)0x${vtableRVA.toString(16)};`);
                    }
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

        for (const [regName, node] of Object.entries(core.regs)) {
            if (node && node.simplify) {
                core.regs[regName] = node.simplify();
            }
        }

        const newStack = new Map();
        for (const [addr, node] of core.stack) {
            newStack.set(addr, node.simplify ? node.simplify() : node);
        }
        core.stack = newStack;
    
        bodyLines = bodyLines.map(line => {
            if (line.includes('++')) return line;
            
            if (line.match(/^\s*(\w+) = (.*);\s*$/) && 
                bodyLines[bodyLines.indexOf(line) + 1]?.includes(`return ${RegExp.$1}`)) {
                return `    return ${RegExp.$2};`;
            }
            
            if (line.includes(' == 0) goto')) {
                return line.replace(/(\w+) == 0\) goto/, '!$1) goto');
            }

            if (line.match(/^\s*push /) && !line.includes('; FPO')) {
                return line.replace(/push (.*);/, '// push $1');
            }
            if (line.match(/^\s*pop /) && !line.includes('; FPO')) {
                return line.replace(/pop (.*);/, '// pop $1');
            }

            // Repl [[...]] to *(*...)
            line = line.replace(/\[\[([^\]]+)\]\]/g, '*(*($1))');
            // Repl mem_[...] to *(...)
            line = line.replace(/mem_\[([^\]]+)\]/g, '*($1)');
            line = line.replace(/undefined/g, '0');
            
            return line;
        });

        bodyLines = bodyLines.filter(line => !line.includes('if (0 >= 0)'));

        if (func.name.includes('10a1') && usesRcx && usesRdx) {
            let hasDisableThreadLibrary = false;
            for (const inst of func.insts) {
                if (inst.text.includes('DisableThreadLibraryCalls')) {
                    hasDisableThreadLibrary = true;
                    break;
                }
            }
            
            if (hasDisableThreadLibrary) {
                functionSignature = `BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)`;
                this.cppLines.push(`    switch (fdwReason) {`);
                this.cppLines.push(`        case DLL_PROCESS_ATTACH:`);
                this.cppLines.push(`            DisableThreadLibraryCalls(hinstDLL);`);
                this.cppLines.push(`            break;`);
                this.cppLines.push(`    }`);
            }
        }
        
        for (let i = 0; i < bodyLines.length; i++) {
            let line = bodyLines[i];
            
            if (line.includes('func_0();')) {
                for (const str of this.strings) {
                    if (str.value === 'GetTickCount' || str.value === 'DisableThreadLibraryCalls' ||
                        str.value === 'QueryPerformanceCounter' || str.value === 'GetCurrentThreadId') {
                        line = line.replace('func_0();', `${str.value}();`);
                        break;
                    }
                }
                bodyLines[i] = line;
            }
            
            if (line.includes('func_0_result')) {
                for (const str of this.strings) {
                    if (str.value === 'GetTickCount') {
                        line = line.replace(/func_0_result/g, 'tickCount');
                        break;
                    }
                }
                bodyLines[i] = line;
            }
        }

        for (let i = 0; i < bodyLines.length; i++) {
            let line = bodyLines[i];
            
            if (line.includes('func_0([rax])')) {
                for (const str of this.strings) {
                    if (str.value === 'GetTickCount') {
                        line = line.replace(/func_0\(\[rax\]\)/g, 'GetTickCount()');
                        break;
                    }
                }
                bodyLines[i] = line;
            }
            
            if (line.includes('func_0([rax])')) {
                for (const str of this.strings) {
                    if (str.value === 'GetTickCount') {
                        line = line.replace(/func_0\(\[rax\]\)/g, 'tickCount');
                        break;
                    }
                }
                bodyLines[i] = line;
            }
            
            if (line.includes('func_0_result')) {
                line = line.replace(/func_0_result/g, 'tickCount');
                bodyLines[i] = line;
            }
        }

        for (let i = 0; i < bodyLines.length; i++) {
            let line = bodyLines[i];
            
            if (line.includes('GetTickCount();') && !line.includes('tickCount')) {
                if (!localVars.has('    DWORD tickCount;')) {
                    localVars.add('    DWORD tickCount;');
                }
                bodyLines[i] = '    tickCount = GetTickCount();';
            }
            
            if (line.includes('GetTickCount()') && !line.includes('tickCount = GetTickCount()')) {
                line = line.replace(/GetTickCount\(\)/g, 'tickCount');
                bodyLines[i] = line;
            }
        }

        if (core.memAccesses) {
            const structCandidates = new Map();
            
            for (const [baseReg, accesses] of Object.entries(core.memAccesses)) {
                const offsets = [...new Set(accesses.map(a => a.offset))].sort((a,b)=>a-b);
                if (offsets.length < 2) continue;
                
                const gaps = [];
                for (let i = 1; i < offsets.length; i++) {
                    gaps.push(offsets[i] - offsets[i-1]);
                }
                
                const possibleSizes = [1, 2, 4, 8, 16];
                let fieldSize = 0;
                for (const size of possibleSizes) {
                    if (offsets.every(offset => offset % size === 0)) {
                        fieldSize = size;
                        break;
                    }
                }
                
                if (fieldSize === 0) continue;
                
                const fieldTypes = [];
                for (const offset of offsets) {
                    const accessAtOffset = accesses.filter(a => a.offset === offset);
                    const sizes = [...new Set(accessAtOffset.map(a => a.size))];
                    const types = [...new Set(accessAtOffset.map(a => a.type))];
                    
                    let fieldType = 'BYTE';
                    if (sizes.includes(8)) fieldType = 'ULONGLONG';
                    else if (sizes.includes(4)) fieldType = 'DWORD';
                    else if (sizes.includes(2)) fieldType = 'WORD';
                    else if (sizes.includes(1)) fieldType = 'BYTE';
                    
                    if (accessAtOffset.some(a => a.type === 'lea' || (a.type === 'mov' && a.size === 8))) {
                        fieldType = 'LPVOID';
                    }
                    
                    const isRead = types.includes('read');
                    const isWrite = types.includes('write');
                    const accessType = isRead && isWrite ? 'read/write' : (isRead ? 'read' : 'write');
                    
                    fieldTypes.push({ 
                        offset, 
                        type: fieldType, 
                        access: accessType, 
                        size: sizes[0] 
                    });
                }

                const structObj = {
                    baseReg,
                    fieldSize,
                    fieldCount: Math.max(...offsets) / fieldSize + 1,
                    offsets,
                    fieldTypes,
                    accesses: accesses.length
                };

                if (detectVTable(accesses, baseReg)) {
                    const vtableMethods = [];
                    const vtableWrite = accesses.find(a => a.offset === 0 && a.type === 'write');
                    if (vtableWrite && vtableWrite.value) {
                        const vtableRVA = vtableWrite.value;
                        const vtableOffset = this.rvaToOffset(vtableRVA);
                        if (vtableOffset !== -1) {
                            let methodIndex = 0;
                            while (true) {
                                const methodRVA = this.view.getUint32(vtableOffset + methodIndex * 4, true);
                                if (methodRVA === 0) break;
                                let methodName = `method_${methodIndex}`;
                                const func = this.functions.find(f => f.start === methodRVA);
                                if (func) {
                                    methodName = func.name;
                                }

                                vtableMethods.push({
                                    index: methodIndex,
                                    rva: methodRVA,
                                    name: methodName
                                });

                                methodIndex++;
                                if (methodIndex > 100) break;
                            }
                        }
                    }

                    structObj.hasVTable = true;
                    structObj.vtableMethods = vtableMethods;
                    structObj.vtableRVA = vtableWrite?.value;
                }
                
                structCandidates.set(baseReg, structObj);
            }
            
            if (structCandidates.size > 0) {
                this.cppLines.unshift('// ========== DETECTED STRUCTURES ==========');
                
                const knownFieldNames = {
                    0x00: 'dwMagic',
                    0x04: 'dwVersion',
                    0x08: 'pfnCallback',
                    0x0c: 'hInstance',
                    0x10: 'lpReserved',
                    0x14: 'dwFlags',
                    0x18: 'pNext'
                };
                
                for (const [baseReg, struct] of structCandidates) {
                    const structName = baseReg === 'rcx' ? 'This' : `Struct_${baseReg.toUpperCase()}`;
                    
                    this.cppLines.unshift(`struct ${structName} {`);
                    
                    for (let i = 0; i <= struct.fieldCount; i++) {
                        const offset = i * struct.fieldSize;
                        const field = struct.fieldTypes.find(f => f.offset === offset);
                        
                        if (field) {
                            let fieldName = knownFieldNames[offset];
                            if (!fieldName) {
                                fieldName = `field_0x${offset.toString(16)}`;
                            }
                            const comment = ` // offset 0x${offset.toString(16)}, ${field.access}`;
                            this.cppLines.unshift(`    ${field.type} ${fieldName};${comment}`);
                        } else if (offset <= Math.max(...struct.offsets)) {
                            this.cppLines.unshift(`    uint8_t padding_0x${offset.toString(16)}[${struct.fieldSize}]; // unknown`);
                        }
                    }
                    
                    this.cppLines.unshift(`};`);
                    this.cppLines.unshift(`// Base register: ${baseReg}, field size: ${struct.fieldSize} bytes, ${struct.accesses} accesses`);
                    this.cppLines.unshift('');
                }

                for (const [baseReg, struct] of structCandidates) {
                    if (struct.hasVTable) {
                        const className = baseReg === 'rcx' ? 'This' : `Class_${baseReg.toUpperCase()}`;
                        
                        this.cppLines.unshift(`class ${className} {`);
                        this.cppLines.unshift(`public:`);
                        
                        if (struct.vtableMethods.length > 0) {
                            this.cppLines.unshift(`    // Virtual function table (vftable)`);
                            this.cppLines.unshift(`    struct VTable {`);
                            for (const method of struct.vtableMethods) {
                                this.cppLines.unshift(`        void (*${method.name})(void*); // offset 0x${(method.index * 8).toString(16)}`);
                            }
                            this.cppLines.unshift(`    };`);
                            this.cppLines.unshift(`    VTable* vptr; // pointer to vftable`);
                            this.cppLines.unshift(``);
                        }
                        
                        for (let i = 0; i <= struct.fieldCount; i++) {
                            const offset = i * struct.fieldSize;
                            const field = struct.fieldTypes.find(f => f.offset === offset);
                            
                            if (field) {
                                let fieldName = knownFieldNames[offset];
                                if (!fieldName) fieldName = `field_0x${offset.toString(16)}`;
                                this.cppLines.unshift(`    ${field.type} ${fieldName}; // offset 0x${offset.toString(16)}`);
                            } else if (offset > 0 && offset <= Math.max(...struct.offsets)) {
                                this.cppLines.unshift(`    uint8_t padding_0x${offset.toString(16)}[${struct.fieldSize}];`);
                            }
                        }
                        
                        this.cppLines.unshift(`};`);
                        this.cppLines.unshift(``);
                    }
                }
                
                this.cppLines.unshift('// ==========================================');
                this.cppLines.unshift('');
                
                for (const [baseReg, struct] of structCandidates) {
                    const structName = baseReg === 'rcx' ? 'This' : `Struct_${baseReg.toUpperCase()}`;
                    
                    for (const field of struct.fieldTypes) {
                        let fieldName = knownFieldNames[field.offset];
                        if (!fieldName) {
                            fieldName = `field_0x${field.offset.toString(16)}`;
                        }
                        
                        const pattern = new RegExp(`\\[${baseReg}\\+0x${field.offset.toString(16)}\\]`, 'g');
                        const replacement = `${structName}->${fieldName}`;
                        
                        bodyLines = bodyLines.map(line => line.replace(pattern, replacement));
                        
                        const doublePattern = new RegExp(`\\[\\[${baseReg}\\+0x${field.offset.toString(16)}\\]\\]`, 'g');
                        const doubleReplacement = `*${structName}->${fieldName}`;
                        
                        bodyLines = bodyLines.map(line => line.replace(doublePattern, doubleReplacement));
                    }
                }

                if (structCandidates.has('rcx') && structCandidates.get('rcx').hasVTable) {
                    const vtable = structCandidates.get('rcx');
                    
                    const vtableCallPattern = /call\s+\[([a-z0-9]+)\+0x([0-9a-f]+)\]/i;
                    for (let i = 0; i < bodyLines.length; i++) {
                        const match = vtableCallPattern.exec(bodyLines[i]);
                        if (match) {
                            const thisReg = match[1];
                            const offset = parseInt(match[2], 16);
                            const methodIndex = offset / 8;
                            
                            const method = vtable.vtableMethods[methodIndex];
                            if (method) {
                                bodyLines[i] = bodyLines[i].replace(
                                    vtableCallPattern,
                                    `${method.name}(this)`
                                );
                            }
                        }
                    }
                }
                
                if (structCandidates.has('rcx')) {
                    functionSignature = functionSignature.replace('void* this_ptr', 'This* this');
                }
            }
        }

        const winapiSignatures = {
            'GetTickCount': { args: [], ret: 'DWORD' },
            'GetCurrentThreadId': { args: [], ret: 'DWORD' },
            'GetCurrentProcessId': { args: [], ret: 'DWORD' },
            'SetLastError': { args: ['DWORD'], ret: 'VOID' },
            'DisableThreadLibraryCalls': { args: ['HMODULE'], ret: 'BOOL' },
            'QueryPerformanceCounter': { args: ['LARGE_INTEGER*'], ret: 'BOOL' },
            'GetSystemTimeAsFileTime': { args: ['LPFILETIME'], ret: 'VOID' }
        };
        
        for (const [funcName, sig] of Object.entries(winapiSignatures)) {
            if (bodyLines.some(line => line.includes(`${funcName}()`))) {
                localVars.add(`    ${sig.ret} ${funcName.toLowerCase()}_result;`);
            }
        }

        for (const func of this.functions) {
            let hasDisableThreadLibrary = false;
            let hasReasonCheck = false;
            
            for (const inst of func.insts) {
                if (inst.text.includes('DisableThreadLibraryCalls')) {
                    hasDisableThreadLibrary = true;
                }
                if (inst.text.includes('cmp') && inst.text.includes('rcx')) {
                    hasReasonCheck = true;
                }
            }
            
            if (hasDisableThreadLibrary && hasReasonCheck) {
                func.name = 'DllMain';
                func.isDllMain = true;
                console.log(`🎯 Found DllMain at 0x${func.start.toString(16)}`);
            }
        }

        const switches = this.detectSwitchCase(func.insts, core);
        if (switches.length > 0) {
            for (const sw of switches) {
                const switchStartLine = bodyLines.findIndex(line => 
                    line.includes(`goto ${sw.tableAddr}`) || 
                    line.includes(`jmp [${sw.indexReg}`)
                );
                
                if (switchStartLine !== -1) {
                    const caseLabels = new Map();
                    
                    for (const caseItem of sw.tableAddr.cases) {
                        caseLabels.set(caseItem.targetLabel, caseItem.value);
                    }
                    
                    let switchBlock = [`    switch (${sw.indexReg} - ${sw.indexShift}) {`];
                    
                    for (const caseItem of sw.tableAddr.cases) {
                        switchBlock.push(`        case ${caseItem.value}:`);
                        switchBlock.push(`            goto ${caseItem.targetLabel};`);
                        switchBlock.push(`            break;`);
                    }
                    
                    switchBlock.push(`        default:`);
                    switchBlock.push(`            break;`);
                    switchBlock.push(`    }`);
                    
                    let endOfSwitch = switchStartLine;
                    while (endOfSwitch < bodyLines.length && 
                           bodyLines[endOfSwitch].includes('if (') && 
                           bodyLines[endOfSwitch].includes('goto')) {
                        endOfSwitch++;
                    }
                    
                    bodyLines.splice(switchStartLine, endOfSwitch - switchStartLine, ...switchBlock);
                }
            }
        }

        this.cppLines.push(...bodyLines);
        this.cppLines.push('}\n');
        
        console.log(`  ✅ Function ${func.name} processed\n`);
        
        core.savedRegs = [];
        core.stackSize = 0;
    }

    detectSwitchCase(instructions, core) {
        const switches = [];
        
        for (let i = 0; i < instructions.length; i++) {
            const inst = instructions[i];
            
            const switchPattern = /jmp \[(.*?)\+.*?\*8/;
            const match = switchPattern.exec(inst.text);
            
            if (match) {
                const tableExpr = match[1];
                console.log(`🔍 Found potential switch at 0x${inst.rva.toString(16)}: ${inst.text}`);
                
                let indexReg = null;
                let indexShift = 0;
                
                for (let j = Math.max(0, i - 10); j < i; j++) {
                    const prevInst = instructions[j];
                    
                    if (prevInst.mnemonic === 'mov' && prevInst.text.includes('eax')) {
                        const regMatch = prevInst.text.match(/mov eax, \[(.*?)\]/);
                        if (regMatch) {
                            indexReg = regMatch[1];
                        }
                    }
                    
                    if (prevInst.mnemonic === 'sub' && prevInst.text.includes('eax')) {
                        const subMatch = prevInst.text.match(/sub eax, 0x([0-9a-f]+)/i);
                        if (subMatch) {
                            indexShift = parseInt(subMatch[1], 16);
                        }
                    }
                }
                
                const tableAddr = this.findJumpTable(tableExpr);
                
                if (tableAddr) {
                    switches.push({
                        rva: inst.rva,
                        tableAddr: tableAddr,
                        indexReg: indexReg || 'eax',
                        indexShift: indexShift,
                        caseCount: tableAddr.cases.length
                    });
                }
            }
        }
        
        return switches;
    }
    
    findJumpTable(tableExpr) {
        let tableRVA = null;
        
        const ripMatch = tableExpr.match(/rip\+0x([0-9a-f]+)/i);
        if (ripMatch) {
            tableRVA = parseInt(ripMatch[1], 16);
        }
        
        const addrMatch = tableExpr.match(/0x([0-9a-f]+)/i);
        if (addrMatch) {
            tableRVA = parseInt(addrMatch[1], 16);
        }
        
        if (!tableRVA) return null;
        
        const section = this.sections.find(s => 
            tableRVA >= s.virtualAddress && 
            tableRVA < s.virtualAddress + s.virtualSize
        );
        
        if (!section) return null;
    
        const offset = section.pointerToRawData + (tableRVA - section.virtualAddress);
        
        const cases = [];
        const maxCases = 256;
        
        for (let i = 0; i < maxCases; i++) {
            const caseOffset = offset + i * 8;
            if (caseOffset + 8 > this.buffer.length) break;
            
            const targetRVA = this.buffer[caseOffset] | 
                             (this.buffer[caseOffset + 1] << 8) |
                             (this.buffer[caseOffset + 2] << 16) |
                             (this.buffer[caseOffset + 3] << 24);
            
            if (targetRVA === 0) break;
            
            cases.push({
                value: i,
                targetRVA: targetRVA,
                targetLabel: `label_0x${targetRVA.toString(16)}`
            });
        }
        
        if (cases.length > 0) {
            return { rva: tableRVA, offset, cases };
        }
        
        return null;
    }
}

class PCPU_Core {
    constructor(binaryBuffer, sections = [], functionNames = new Map(), apiNames = new Map(), is32bit = false) {
        if (typeof GUECMan !== 'undefined') {
            GUECMan.ConnectToClass(this);
        }
        
        this.is32bit = is32bit;
        this.functionNames = functionNames;
        this.apiNames = apiNames;
        this.buffer = binaryBuffer;
        this.sections = sections;
        this.imageBase = is32bit ? 0x400000 : 0x140000000;
        this.ip = 0;
        this.statements = [];
        this.regs = this.initRegisters();
        this.stack = new Map();
        this.globalMemory = new Map();
        this.flags = { 
            zf: false, sf: false, cf: false, of: false, df: false, pf: false,
            lastCompAST: null, lastComp: ""
        };
        this.memoryCache = new Map();
        this.memoryWrites = [];
        this.fpoDeoptimizer = null;
        this.functions = [];
        this.currentFunction = null;
        this.currentFPOInfo = null;
        this.savedRegs = [];
        this.stackSize = 0;
        this.hasRBPStackFrame = false;
        this.foundReturns = 0;
        this.fpoDetected = false;
        this.rexPrefix = null;
        this.repPrefix = null;
        this.lockPrefix = false;
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
        0x7D: { mnem: "jnl", len: 2 },
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
        this.memAccesses = new Map();
        this.imports = [];
        this.initFPODeoptimizer();
    }
 
    initRegisters() {
        const regs = {};
        const regNames = this.is32bit 
            ? ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            : ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
        
        for (const name of regNames) {
            regs[name] = new ASTNode('reg', name);
        }
        
        if (!this.is32bit) {
            regs.r8 = new ASTNode('reg', 'r8');
            regs.r9 = new ASTNode('reg', 'r9');
            regs.r10 = new ASTNode('reg', 'r10');
            regs.r11 = new ASTNode('reg', 'r11');
            regs.r12 = new ASTNode('reg', 'r12');
            regs.r13 = new ASTNode('reg', 'r13');
            regs.r14 = new ASTNode('reg', 'r14');
            regs.r15 = new ASTNode('reg', 'r15');
        }
        
        return regs;
    }
    
    initFPODeoptimizer() {
        const instructions = this.extractInstructions();
        
        this.fpoDeoptimizer = new FPODeoptimizer(
            instructions,
            this.buffer,
            this.imageBase
        );
        
        this.functions = this.fpoDeoptimizer.analyzeFunctionBoundaries();
    }
    
    extractInstructions() {
        const instructions = [];
        let ip = 0;
        
        while (ip < this.buffer.length) {
            const inst = this.fetchAt(ip);
            if (!inst) break;
            
            instructions.push({
                rva: ip,
                mnemonic: inst.mnemonic,
                text: inst.text,
                bytes: inst.bytes,
                length: inst.len
            });
            
            ip += inst.len;
        }
        
        return instructions;
    }
    
    analyzeFunctions() {
        if (!this.fpoDeoptimizer) {
            this.initFPODeoptimizer();
        }
        
        const functions = this.fpoDeoptimizer.functions;
        
        console.log(`[PCPU] Found ${functions.length} functions`);
        console.log(`  - STD (with RBP): ${functions.filter(f => f.type === 'std').length}`);
        console.log(`  - FPO (no RBP): ${functions.filter(f => f.type === 'fpo').length}`);
        console.log(`  - FPO32: ${functions.filter(f => f.type === 'fpo32').length}`);
        console.log(`  - Hotpatch: ${functions.filter(f => f.type === 'hotpatch').length}`);
        
        return functions;
    }
    
    getFunctionAt(ip) {
        for (const func of this.functions) {
            if (ip >= func.start && ip <= (func.end || Infinity)) {
                return func;
            }
        }
        return null;
    }
 
    resolveAddress(m) {
        const ptrSize = this.is32bit ? 4 : 8;
        const spReg = this.is32bit ? 'esp' : 'rsp';
        const bpReg = this.is32bit ? 'ebp' : 'rbp';
        
        const fpoInfo = this.getCurrentFPOInfo();
        
        if (fpoInfo && m.rmName === spReg) {
            const savedRegsSize = fpoInfo.savedRegs.length * ptrSize;
            const shadowSpace = fpoInfo.hasShadowSpace ? fpoInfo.shadowSize : 0;
            const totalSaved = savedRegsSize + shadowSpace;
            
            let finalOffset;
            const offset = m.offset || 0;
            
            if (offset < totalSaved) {
                finalOffset = offset - totalSaved;
                return `${bpReg} ${finalOffset >= 0 ? '+' : '-'} 0x${Math.abs(finalOffset).toString(16)}`;
            } else if (offset < totalSaved + fpoInfo.stackSize) {
                const localOffset = offset - totalSaved;
                finalOffset = -(fpoInfo.stackSize - localOffset);
                return `${bpReg} - 0x${Math.abs(finalOffset).toString(16)}`;
            } else {
                const argOffset = offset - totalSaved - fpoInfo.stackSize;
                finalOffset = 0x10 + argOffset;
                return `${bpReg} + 0x${finalOffset.toString(16)}`;
            }
        }
        
        if (m.offset !== undefined && m.offset !== 0) {
            const sign = m.offset > 0 ? '+' : '-';
            const absOffset = Math.abs(m.offset);
            return `${m.rmName} ${sign} 0x${absOffset.toString(16)}`;
        }
        
        return m.rmName;
    }
    
    getCurrentFPOInfo() {
        if (!this.currentFunction) return null;
        if (this.currentFunction.type !== 'fpo' && this.currentFunction.type !== 'fpo32') return null;
        
        return {
            savedRegs: this.currentFunction.savedRegs || [],
            stackSize: this.currentFunction.stackSize || 0,
            hasShadowSpace: this.currentFunction.hasShadowSpace || false,
            shadowSize: this.currentFunction.shadowSize || 0,
            is32bit: this.currentFunction.is32bit || this.is32bit
        };
    }
    
    readFromBuffer(offset, size) {
        if (offset === -1 || offset + size > this.buffer.length) {
            return 0;
        }
        
        let value = 0;
        for (let i = 0; i < size; i++) {
            value |= this.buffer[offset + i] << (i * 8);
        }
        return value;
    }
    
    readMemoryValue(addr, size) {
        if (typeof addr !== 'number') return null;
        
        const cacheKey = `${addr}_${size}`;
        if (this.memoryCache.has(cacheKey)) {
            return this.memoryCache.get(cacheKey);
        }
        
        const offset = this.rvaToOffset(addr);
        if (offset !== -1 && offset + size <= this.buffer.length) {
            let value = 0;
            for (let i = 0; i < size; i++) {
                value |= this.buffer[offset + i] << (i * 8);
            }
            this.memoryCache.set(cacheKey, value);
            return value;
        }
        return null;
    }
    
    memoryRead(addr, size) {
        let addrValue = addr;
        
        if (addr && addr.type === 'const') {
            addrValue = addr.value;
        } else if (addr && addr.type === 'add') {
            const left = this.tryGetValue(addr.left);
            const right = this.tryGetValue(addr.right);
            if (left !== null && right !== null) {
                addrValue = left + right;
            }
        } else if (addr && addr.type === 'reg') {
            addrValue = addr.value;
        }
        
        const addrKey = addrValue?.toString() || addr?.toString() || '?';
        
        for (const [stackAddr, value] of this.stack) {
            if (stackAddr === addrKey || stackAddr.includes(addrKey)) {
                return value.clone();
            }
        }
        
        if (this.globalMemory && this.globalMemory.has(addrKey)) {
            return this.globalMemory.get(addrKey);
        }
        
        if (typeof addrValue === 'number') {
            const value = this.readMemoryValue(addrValue, size);
            if (value !== null) {
                return new ASTNode('const', value);
            }
        }
        
        const strValue = this.resolveStringConstant(addrValue);
        if (strValue) {
            return new ASTNode('const', `"${strValue}"`);
        }
        
        return new ASTNode('reg', `mem_${addrKey.replace(/[^a-zA-Z0-9_]/g, '_')}`);
    }
    
    memoryWrite(addr, value, size) {
        let addrValue = addr;
        
        if (addr && addr.type === 'const') {
            addrValue = addr.value;
        } else if (addr && addr.type === 'add') {
            const left = this.tryGetValue(addr.left);
            const right = this.tryGetValue(addr.right);
            if (left !== null && right !== null) {
                addrValue = left + right;
            }
        }
        
        const addrStr = addrValue?.toString() || addr?.toString() || '?';
        this.globalMemory.set(addrStr, value.clone());
        this.memoryWrites.push({
            addr: addr,
            value: value,
            size: size,
            rva: this.ip
        });
        
        if (typeof addrValue === 'number') {
            return `*(int${size*8}_t*)0x${addrValue.toString(16)} = ${value.toString()};`;
        }
        return `[${addr.toString()}] = ${value.toString()};`;
    }
    
    resolveStringConstant(addr) {
        if (typeof addr !== 'number') return null;
        
        const offset = this.rvaToOffset(addr);
        if (offset === -1) return null;
        
        let asciiStr = '';
        let i = 0;
        while (offset + i < this.buffer.length && this.buffer[offset + i] !== 0 && i < 256) {
            const c = this.buffer[offset + i];
            if (c >= 0x20 && c <= 0x7E) {
                asciiStr += String.fromCharCode(c);
            } else {
                break;
            }
            i++;
        }
        if (asciiStr.length >= 4 && !asciiStr.match(/^[0-9a-fA-F]+$/)) {
            return asciiStr;
        }
        
        let utf16Str = '';
        i = 0;
        while (offset + i + 1 < this.buffer.length && 
               (this.buffer[offset + i] !== 0 || this.buffer[offset + i + 1] !== 0) && i < 512) {
            const c = this.buffer[offset + i] | (this.buffer[offset + i + 1] << 8);
            if (c >= 0x20 && c <= 0x7E) {
                utf16Str += String.fromCharCode(c);
            } else {
                break;
            }
            i += 2;
        }
        if (utf16Str.length >= 4 && !utf16Str.match(/^[0-9a-fA-F]+$/)) {
            return utf16Str;
        }
        
        return null;
    }
    
    tryGetValue(node) {
        if (!node) return null;
        if (node.type === 'const') return node.value;
        if (node.type === 'reg') {
            const regValue = this.regs[node.value];
            if (regValue && regValue.type === 'const') {
                return regValue.value;
            }
        }
        if (node.type === 'add') {
            const left = this.tryGetValue(node.left);
            const right = this.tryGetValue(node.right);
            if (left !== null && right !== null) return left + right;
        }
        if (node.type === 'sub') {
            const left = this.tryGetValue(node.left);
            const right = this.tryGetValue(node.right);
            if (left !== null && right !== null) return left - right;
        }
        return null;
    }
 
    rvaToOffset(rva) {
        if (rva === 0) return -1;
        
        const rvaNum = typeof rva === 'bigint' ? Number(rva) : rva;
        
        let textSection = null;
        for (const section of this.sections) {
            if (section.name === '.text') {
                textSection = section;
                break;
            }
        }
        
        if (!textSection) {
            const textStart = 0x1000;
            const textEnd = 0x1800;
            const textRawOffset = 0x400;
            
            if (rvaNum >= textStart && rvaNum < textEnd) {
                const offset = textRawOffset + (rvaNum - textStart);
                if (offset >= 0 && offset < this.buffer.length) {
                    return offset;
                }
            }
            return -1;
        }
        
        const sectionStart = textSection.virtualAddress;
        const sectionEnd = sectionStart + textSection.virtualSize;
        
        if (rvaNum >= sectionStart && rvaNum < sectionEnd) {
            if (textSection.pointerToRawData === 0) {
                return -1;
            }
            
            const offset = textSection.pointerToRawData + (rvaNum - sectionStart);
            if (offset >= 0 && offset < this.buffer.length) {
                return offset;
            }
        }
        
        return -1;
    }
    
    fetchAt(ip) {
        if (ip >= this.buffer.length) return null;
        
        let byte = this.buffer[ip];
        let instInfo;
        
        if (byte === 0x0F) {
            if (ip + 1 >= this.buffer.length) return null;
            const secondByte = this.buffer[ip + 1];
            instInfo = this.opcodeTable2Byte[secondByte] || { mnem: "db", len: 2 };
            instInfo.bytes = this.buffer.slice(ip, ip + instInfo.len);
        } else {
            instInfo = this.opcodeTable[byte] || { mnem: "db", len: 1 };
            instInfo.bytes = this.buffer.slice(ip, ip + instInfo.len);
        }
        
        return {
            mnemonic: instInfo.mnem,
            len: instInfo.len,
            bytes: instInfo.bytes,
            text: this.formatInstruction(instInfo, ip),
            rva: ip
        };
    }
    
    formatInstruction(instInfo, ip) {
        const bytes = instInfo.bytes;
        const mnem = instInfo.mnem;
        
        if (mnem === 'db') {
            return `db ${Array.from(bytes).map(b => '0x' + b.toString(16)).join(', ')}`;
        }
        
        let result = mnem;
        
        if (bytes.length > 1) {
            if (bytes[1] >= 0x80 || (bytes[0] >= 0x88 && bytes[0] <= 0x8F)) {
                const modrm = this.decodeModRMAt(ip);
                if (modrm) {
                    result += ` ${modrm.regName}, ${modrm.rmName}`;
                }
            } else if (bytes.length >= 5 && (bytes[0] === 0xE8 || bytes[0] === 0xE9)) {
                const offset = bytes[1] | (bytes[2] << 8) | (bytes[3] << 16) | (bytes[4] << 24);
                const target = ip + 5 + offset;
                result += ` 0x${target.toString(16)}`;
            } else if (bytes.length >= 2 && (bytes[0] === 0xEB || (bytes[0] >= 0x70 && bytes[0] <= 0x7F))) {
                const offset = bytes[1];
                const target = ip + 2 + (offset > 127 ? offset - 256 : offset);
                result += ` 0x${target.toString(16)}`;
            }
        }
        
        return result;
    }
    
    decodeModRMAt(ip) {
        if (ip + 1 >= this.buffer.length) return null;
        
        const bytes = this.buffer.slice(ip, ip + 8);
        const modrm = bytes[1];
        const mod = (modrm >> 6) & 3;
        const reg = (modrm >> 3) & 7;
        const rm = modrm & 7;
        
        const regNames = this.is32bit 
            ? ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            : ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
        
        let rmExpr = regNames[rm];
        let offset = 0;
        
        if (mod === 1 && bytes.length > 2) {
            offset = bytes[2];
            if (offset > 127) offset -= 256;
            rmExpr = `${regNames[rm]} ${offset >= 0 ? '+' : '-'} 0x${Math.abs(offset).toString(16)}`;
        } else if (mod === 2 && bytes.length > 5) {
            offset = bytes[2] | (bytes[3] << 8) | (bytes[4] << 16) | (bytes[5] << 24);
            rmExpr = `${regNames[rm]} ${offset >= 0 ? '+' : '-'} 0x${Math.abs(offset).toString(16)}`;
        }
        
        return {
            mod: mod,
            regName: regNames[reg],
            rmName: rmExpr,
            isDirect: mod === 3,
            offset: offset
        };
    }
    
    decodeModRM(bytes) {
        if (bytes.length < 2) return null;
        
        const modrm = bytes[1];
        const mod = (modrm >> 6) & 3;
        const reg = (modrm >> 3) & 7;
        const rm = modrm & 7;
        
        const regNames = this.is32bit 
            ? ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            : ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
        
        let rmExpr = regNames[rm];
        let offset = 0;
        
        if (mod === 0 && rm === 5) {
            if (bytes.length > 6) {
                offset = bytes[2] | (bytes[3] << 8) | (bytes[4] << 16) | (bytes[5] << 24);
                if (this.is32bit) {
                    rmExpr = `0x${offset.toString(16)}`;
                } else {
                    rmExpr = `rip+0x${offset.toString(16)}`;
                }
            }
        } else if (mod === 1 && bytes.length > 2) {
            offset = bytes[2];
            if (offset > 127) offset -= 256;
            rmExpr = `${regNames[rm]} ${offset >= 0 ? '+' : '-'} 0x${Math.abs(offset).toString(16)}`;
        } else if (mod === 2 && bytes.length > 5) {
            offset = bytes[2] | (bytes[3] << 8) | (bytes[4] << 16) | (bytes[5] << 24);
            rmExpr = `${regNames[rm]} ${offset >= 0 ? '+' : '-'} 0x${Math.abs(offset).toString(16)}`;
        }
        
        return {
            mod: mod,
            regName: regNames[reg],
            rmName: rmExpr,
            isDirect: mod === 3,
            offset: offset,
            hasSib: (mod !== 3 && rm === 4)
        };
    }
    
    getOperandSize(bytes) {
        const opcode = bytes[0];
        const hasRex = (opcode & 0xF0) === 0x40 && opcode >= 0x40 && opcode <= 0x4F;
        const rexW = hasRex && (opcode & 0x08) !== 0;
        
        if (this.is32bit) {
            if (opcode >= 0x88 && opcode <= 0x8F) return 1;
            if (opcode >= 0x89 && opcode <= 0x8B) return 4;
            if (opcode === 0xC7) return 4;
            if (opcode === 0x66) return 2;
            return 4;
        } else {
            if (rexW && (opcode >= 0x89 && opcode <= 0x8B)) return 8;
            if (opcode >= 0x88 && opcode <= 0x8F) return 1;
            if (opcode >= 0x89 && opcode <= 0x8B) return 4;
            if (opcode === 0xC7) return 4;
            if (opcode === 0x66) return 2;
            return 8;
        }
    }

    stackPush(data) {
        const ptrSize = this.is32bit ? 4 : 8;
        const spReg = this.is32bit ? 'esp' : 'rsp';
        
        this.regs[spReg] = new ASTNode(
            'sub', null,
            this.regs[spReg].clone(),
            new ASTNode('const', ptrSize)
        );
        this.stack.set(this.regs[spReg].toString(), data);
        this.statements.push(`push ${data.toString()};`);
    }
    
    stackPop() {
        const spReg = this.is32bit ? 'esp' : 'rsp';
        const ptrSize = this.is32bit ? 4 : 8;
        const addr = this.regs[spReg].toString();
        const data = this.stack.get(addr) || new ASTNode('reg', `pop_val_${addr}`);
        
        this.regs[spReg] = new ASTNode(
            'add', null,
            this.regs[spReg].clone(),
            new ASTNode('const', ptrSize)
        );
        return data;
    }

    fetchNext() {
        let byte = this.buffer[this.ip];
        let instInfo;
        
        if (byte === 0x0F) {
            this.ip++;
            byte = this.buffer[this.ip];
            instInfo = this.opcodeTable2Byte[byte] || { mnem: "db", len: 1 };
        } else {
            instInfo = this.opcodeTable[byte] || { mnem: "db", len: 1 };
        }
        
        const rawInst = this.buffer.slice(this.ip, this.ip + instInfo.len);
        this.ip += instInfo.len;
        
        return { ...instInfo, bytes: rawInst };
    }
    
    run(steps = 100) {
        for (let i = 0; i < steps; i++) {
            const inst = this.fetchNext();
            if (inst.mnem === "ret") break;
            
            this.currentFunction = this.getFunctionAt(this.ip);
            this.currentFPOInfo = this.getCurrentFPOInfo();
            
            this.execute(inst);
        }
    }

    getOpcodeInfo(bytes) {
        const opcode = bytes[0];
        const second = bytes[1];
        
        const knownOpcodes = {
            0x0F: {
                0x00: "SLDT / SGDT / STR / SMSW",
                0x01: "LGDT / LIDT / LLDT / LMSW / INVLPG / SWAPGS / RDTSCP",
                0x05: "SYSCALL",
                0x06: "CLTS",
                0x07: "SYSRET",
                0x08: "INVD",
                0x09: "WBINVD",
                0x0B: "UD2",
                0x0D: "PREFETCH",
                0x1F: "NOP (multi-byte)",
                0x31: "RDTSC",
                0x34: "SYSENTER",
                0x35: "SYSEXIT",
                0xA2: "CPUID",
                0xAF: "IMUL",
                0xB0: "CMPXCHG",
                0xB1: "CMPXCHG",
                0xB6: "MOVZX",
                0xB7: "MOVZX",
                0xBE: "MOVSX",
                0xBF: "MOVSX",
                0xC7: "CMPXCHG8B / CMPXCHG16B"
            },
            0xCD: { 0x2E: "INT 2E (old syscall)" },
            0xCC: { 0x00: "INT 3 breakpoint" }
        };
        
        if (knownOpcodes[opcode] && knownOpcodes[opcode][second]) {
            return knownOpcodes[opcode][second];
        }
        
        if (opcode >= 0x70 && opcode <= 0x7F) {
            const cond = ['JO', 'JNO', 'JB', 'JNB', 'JZ', 'JNZ', 'JBE', 'JNBE', 
                          'JS', 'JNS', 'JP', 'JNP', 'JL', 'JNL', 'JLE', 'JNLE'][opcode - 0x70];
            return `${cond} (conditional jump)`;
        }
        
        if (opcode >= 0x50 && opcode <= 0x57) {
            const reg = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'][opcode - 0x50];
            return `PUSH ${reg}`;
        }
        
        if (opcode >= 0x58 && opcode <= 0x5F) {
            const reg = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'][opcode - 0x58];
            return `POP ${reg}`;
        }
        
        return null;
    }
    
    getDecompilerHeader() {
        this.fpoDetected = this.foundReturns > 0 && !this.hasRBPStackFrame;
        
        let report = "// Generated by RSDEFD C++ Decompiler v2.0\n";
        report += "// Decompiled C++ based by JS CPU calculations\n";
        
        if (this.fpoDetected) {
            report += "// C++ JSCPU Decomp: This Portable Executable contains FPO (Frame Pointer Omission)\n";
            report += "// ⚠️ Warning: Standard stack frame analysis (RBP-based) is disabled.\n";
        }
        
        if (this.functions && this.functions.length > 0) {
            const fpoCount = this.functions.filter(f => f.type === 'fpo' || f.type === 'fpo32').length;
            if (fpoCount > 0) {
                report += `// 📊 Detected ${fpoCount} FPO-optimized functions (will be deoptimized)\n`;
            }
        }
        
        return report;
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
            case 'leave': {
                this.statements.push(`mov rsp, rbp;  // leave (restore stack pointer)`);
                this.statements.push(`pop rbp;       // restore frame pointer`);
                break;
            }
            case 'movsb':
                this.statements.push(`*rdi++ = *rsi++;  // movsb (copy byte)`);
                break;
            case 'movsw':
                this.statements.push(`*(WORD*)rdi++ = *(WORD*)rsi++;  // movsw (copy word)`);
                break;
            case 'stosb':
                this.statements.push(`*rdi++ = al;  // stosb (store byte)`);
                break;
            case 'lodsb':
                this.statements.push(`al = *rsi++;  // lodsb (load byte)`);
                break;
            case 'adc': {
                const a = this.decodeModRM(bytes);
                if (!this.regs[a.regName] || !this.regs[a.rmName]) {
                    this.statements.push(`// adc ${a.regName}, ${a.rmName} (cannot emulate - carry flag)`);
                    break;
                }
                const carry = this.flags.cf ? new ASTNode('const', 1) : new ASTNode('const', 0);
                const sum = new ASTNode('add', null, this.regs[a.regName].clone(), this.regs[a.rmName].clone());
                this.regs[a.regName] = new ASTNode('add', null, sum, carry);
                this.statements.push(`${a.regName} = ${this.regs[a.regName].toString()};`);
                break;
            }
            case 'sbb': {
                const a = this.decodeModRM(bytes);
                if (!this.regs[a.regName] || !this.regs[a.rmName]) {
                    this.statements.push(`// sbb ${a.regName}, ${a.rmName} (cannot emulate - borrow flag)`);
                    break;
                }
                const left = this.regs[a.regName].l;
                const right = this.regs[a.rmName].l;
                const borrow = this.flags.cf ? ' - 1' : '';
                this.regs[a.regName].l = `(${left} - ${right}${borrow})`;
                this.statements.push(`${a.regName} = ${this.regs[a.regName].l};`);
                break;
            }
            case 'aaa':
                this.statements.push(`// aaa (ASCII adjust after addition) - obsolete instruction`);
                break;
            case 'sldt':
                this.statements.push(`// sldt (store local descriptor table) - privileged instruction, cannot emulate`);
                break;
            case 'repne':
            case 'repe':
            case 'rep':
                const repType = mnem === 'repne' ? 'repeat while not equal' : 
                                mnem === 'repe' ? 'repeat while equal' : 'repeat';
                this.statements.push(`// ${mnem} (${repType} prefix) - repeats following string instruction`);
                this.repPrefix = mnem;
                break;
            case 'lock':
                this.statements.push(`// lock (atomic operation prefix) - ensures exclusive memory access for next instruction`);
                this.lockPrefix = true;
                break; 
            case 'clc':
                this.statements.push(`// clc (clear carry flag) - sets CF=0`);
                this.flags.cf = false;
                this.flags.lastComp = '';
                break;   
            case 'stc':
                this.statements.push(`// stc (set carry flag) - sets CF=1`);
                this.flags.cf = true;
                this.flags.lastComp = '';
                break;
            case 'cmc':
                this.statements.push(`// cmc (complement carry flag) - toggles CF`);
                this.flags.cf = !this.flags.cf;
                break;
            case 'cld':
                this.statements.push(`// cld (clear direction flag) - DF=0, string operations increment`);
                this.flags.df = false;
                break;
            case 'std':
                this.statements.push(`// std (set direction flag) - DF=1, string operations decrement`);
                this.flags.df = true;
                break;
            case 'cli':
                this.statements.push(`// cli (clear interrupt flag) - disables interrupts (privileged, kernel-mode only)`);
                this.flags.if = false;
                break;
            case 'sti':
                this.statements.push(`// sti (set interrupt flag) - enables interrupts (privileged, kernel-mode only)`);
                this.flags.if = true;
                break;
            case 'hlt':
                this.statements.push(`// hlt (halt CPU) - stops execution until interrupt/reset (privileged)`);
                break;
            case 'das':
                this.statements.push(`// das (decimal adjust after subtraction) - obsolete BCD instruction (x86 only)`);
                break;
            case 'aas':
                this.statements.push(`// aas (ASCII adjust after subtraction) - obsolete BCD instruction`);
                break;
            case 'daa':
                this.statements.push(`// daa (decimal adjust after addition) - obsolete BCD instruction`);
                break;
            case 'salc':
                this.statements.push(`// salc (set AL to carry flag) - undocumented instruction, sets AL=0xFF if CF=1 else 0`);
                const setVal = this.flags.cf ? '0xFF' : '0';
                this.regs.al = new ASTNode('const', setVal);
                this.statements.push(`al = ${setVal};  // salc (set AL from carry)`);
                break;  
            case 'xlat':
                this.statements.push(`// xlat (translate byte) - al = [ebx + al]`);
                const xlatAddr = this.is32bit ? 
                    new ASTNode('add', null, this.regs.ebx.clone(), this.regs.eax.clone()) :
                    new ASTNode('add', null, this.regs.rbx.clone(), this.regs.rax.clone());
                const xlatValue = this.memoryRead(xlatAddr, 1);
                if (this.is32bit) {
                    this.regs.al = xlatValue;
                    this.statements.push(`al = ${xlatValue.toString()};  // xlat (translate byte)`);
                } else {
                    this.regs.rax = xlatValue;
                    this.statements.push(`al = ${xlatValue.toString()};  // xlat (translate byte)`);
                }
                break;
            case 'bswap':
                const bswapMatch = inst.text.match(/bswap (r[a-z]+)/i);
                if (bswapMatch) {
                    const reg = bswapMatch[1];
                    this.statements.push(`// bswap ${reg} - byte swap (reverse endianness)`);
                    this.regs[reg] = new ASTNode('reg', `${reg}_swapped`);
                } else {
                    this.statements.push(`// bswap - byte swap (reverse endianness)`);
                }
                break;
            case 'cpuid':
                this.statements.push(`// cpuid - CPU identification (returns vendor string in ebx/ecx/edx)`);
                this.regs.ebx = new ASTNode('const', 0x756E6547);
                this.regs.ecx = new ASTNode('const', 0x6C65746E);
                this.regs.edx = new ASTNode('const', 0x49656E69);
                break;  
            case 'rdtsc':
                this.statements.push(`// rdtsc - read timestamp counter (returns CPU cycles)`);
                const timestamp = Date.now() * 1000000;
                if (this.is32bit) {
                    this.regs.eax = new ASTNode('const', timestamp & 0xFFFFFFFF);
                    this.regs.edx = new ASTNode('const', (timestamp >> 32) & 0xFFFFFFFF);
                    this.statements.push(`eax = 0x${(timestamp & 0xFFFFFFFF).toString(16)};  // low 32 bits`);
                    this.statements.push(`edx = 0x${((timestamp >> 32) & 0xFFFFFFFF).toString(16)};  // high 32 bits`);
                } else {
                    this.regs.rax = new ASTNode('const', timestamp);
                    this.regs.eax = new ASTNode('const', timestamp & 0xFFFFFFFF);
                    this.regs.edx = new ASTNode('const', (timestamp >> 32) & 0xFFFFFFFF);
                    this.statements.push(`rax = 0x${timestamp.toString(16)};  // full 64-bit timestamp`);
                }
                break;  
            case 'rdmsr':
                this.statements.push(`// rdmsr - read model-specific register (privileged, kernel-mode only)`);
                this.regs.eax = new ASTNode('reg', 'msr_low');
                this.regs.edx = new ASTNode('reg', 'msr_high');
                break;
            case 'wrmsr':
                this.statements.push(`// wrmsr - write model-specific register (privileged, kernel-mode only)`);
                break; 
            case 'syscall':
                this.statements.push(`// syscall - fast system call (64-bit Windows/Linux)`);
                break;
            case 'sysenter':
                this.statements.push(`// sysenter - fast system call (32-bit Windows)`);
                break
            case 'sysexit':
                this.statements.push(`// sysexit - fast return from system call (privileged)`);
                break;
            case 'int':
                const intNum = bytes[1] || 0;
                if (intNum === 0x2E) {
                    this.statements.push(`// int 0x2E - old-style system call (Windows 9x/NT)`);
                } else if (intNum === 0x2D) {
                    this.statements.push(`// int 0x2D - KiFastSystemCall (Windows NT)`);
                } else {
                    this.statements.push(`// int 0x${intNum.toString(16)} - software interrupt (vector ${intNum})`);
                }
                break;
            case 'into':
                this.statements.push(`// into - interrupt on overflow (if OF=1, int 4)`);
                break;  
            case 'iret':
                this.statements.push(`// iret - return from interrupt (privileged)`);
                break;
            case 'movq':
            case 'addq':
            case 'subq':
            case 'xorq':
            case 'andq':
            case 'orq':
                const q = this.decodeModRM(bytes);
                const opSymQ = { 'addq': '+', 'subq': '-', 'xorq': '^', 'andq': '&', 'orq': '|' }[mnem];
                if (mnem === 'xorq' && q.regName === q.rmName) {
                    this.regs[q.regName] = { v: 0, l: "0" };
                } else {
                    this.regs[q.regName].l = `(${this.regs[q.regName].l} ${opSymQ} ${this.regs[q.rmName].l})`;
                }
                break;
            case 'js':
                if (!this.flags.lastComp || this.flags.lastComp === '') {
                    this.statements.push(`// js (sign) condition at 0x${inst.rva?.toString(16)} - unknown condition`);
                } else {
                    this.statements.push(`if ((${this.flags.lastComp}) < 0) goto label_0x...;`);
                }
                break;
            case 'jns':
                this.statements.push(`if ((${this.flags.lastComp}) >= 0) goto label_0x...;`);
                break;
            case 'jle':
                this.statements.push(`if ((${this.flags.lastComp}) <= 0) goto label_0x...;`);
                break;
            case 'jg':
                this.statements.push(`if ((${this.flags.lastComp}) > 0) goto label_0x...;`);
                break;
            case 'jbe':
                this.statements.push(`if ((${this.flags.lastComp}) <= 0) goto label_0x...;`);
                break;
            case 'ja':
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
            case 'rex.40':
            case 'rex.41':
            case 'rex.42':
            case 'rex.43':
            case 'rex.44':
            case 'rex.45':
            case 'rex.46':
            case 'rex.47':
            case 'rex.48':
            case 'rex.49':
            case 'rex.4a':
            case 'rex.4b':
            case 'rex.4c':
            case 'rex.4d':
            case 'rex.4e':
            case 'rex.4f':
                const rexByte = bytes[0];
                this.rexPrefix = {
                    w: (rexByte & 0x08) !== 0,
                    r: (rexByte & 0x04) !== 0,
                    x: (rexByte & 0x02) !== 0,
                    b: (rexByte & 0x01) !== 0
                };
                break;
            case 'movsb':
            case 'movsw':
            case 'movsd':
            case 'movsq':
                const movSize = mnem === 'movsb' ? 1 : (mnem === 'movsw' ? 2 : (mnem === 'movsd' ? 4 : 8));
                const dirFlag = this.flags.df ? -1 : 1;
                const srcReg = this.is32bit ? 'esi' : 'rsi';
                const dstReg = this.is32bit ? 'edi' : 'rdi';
                
                if (this.repPrefix) {
                    this.statements.push(`// ${this.repPrefix} ${mnem} - copy ${movSize} byte(s) repeated ECX times`);
                    this.statements.push(`memcpy(${dstReg}, ${srcReg}, ${this.is32bit ? 'ecx' : 'rcx'} * ${movSize});`);
                    this.statements.push(`${dstReg} += ${this.is32bit ? 'ecx' : 'rcx'} * ${movSize};`);
                    this.statements.push(`${srcReg} += ${this.is32bit ? 'ecx' : 'rcx'} * ${movSize};`);
                    if (this.is32bit) this.regs.ecx = new ASTNode('const', 0);
                    else this.regs.rcx = new ASTNode('const', 0);
                    this.repPrefix = null;
                } else {
                    this.statements.push(`*(${dstReg}) = *(${srcReg});  // ${mnem} (copy ${movSize} byte(s))`);
                    this.statements.push(`${dstReg} += ${movSize * dirFlag};`);
                    this.statements.push(`${srcReg} += ${movSize * dirFlag};`);
                }
                break;
            case 'mov':
            case 'movzx':
            case 'movsx': {
                const m = this.decodeModRM(bytes);
                
                if (!this.regs[m.regName]) {
                    this.statements.push(`// Unknown mov: ${inst.text}`);
                    break;
                }
            
                if (!m.isDirect) {
                    const addr = this.resolveAddress(m);
                    const value = this.regs[m.regName];
                    const size = this.getOperandSize(bytes);
                    
                    const writeStmt = this.memoryWrite(addr, value, size);
                    this.statements.push(writeStmt);
                    
                    if (!this.memAccesses) this.memAccesses = {};
                    const baseReg = m.rmName;
                    if (!this.memAccesses[baseReg]) this.memAccesses[baseReg] = [];
                    this.memAccesses[baseReg].push({
                        offset: m.offset,
                        size: size,
                        type: 'write',
                        rva: inst.rva
                    });
                } else {
                    if (!this.regs[m.rmName]) {
                        this.statements.push(`// Unknown mov: ${inst.text}`);
                        break;
                    }
                    
                    const addr = this.resolveAddress(m);
                    const size = this.getOperandSize(bytes);
                    
                    const memValue = this.memoryRead(addr, size);
                    this.regs[m.regName] = memValue;
                    
                    if (memValue.type === 'const') {
                        this.statements.push(`${m.regName} = 0x${memValue.value.toString(16)};`);
                    } else {
                        this.statements.push(`${m.regName} = ${memValue.toString()};`);
                    }
                    
                    if (!this.memAccesses) this.memAccesses = {};
                    const baseReg = m.rmName;
                    if (!this.memAccesses[baseReg]) this.memAccesses[baseReg] = [];
                    this.memAccesses[baseReg].push({
                        offset: m.offset,
                        size: size,
                        type: 'read',
                        rva: inst.rva
                    });
                }
                break;
            }
    
            case 'lea': {
                const l = this.decodeModRM(bytes);
                const fpoInfo = this.getCurrentFPOInfo();

                if (!l.isDirect) {
                    const baseReg = l.rmName;
                    const offset = l.offset;
                    
                    if (!this.memAccesses) this.memAccesses = {};
                    if (!this.memAccesses[baseReg]) this.memAccesses[baseReg] = [];
                    
                    this.memAccesses[baseReg].push({
                        offset: offset,
                        size: this.getOperandSize(bytes),
                        type: mnem,
                        rva: inst.rva
                    });
                }
                
                // FPO: lea rbx, [rsp+0x20] -> lea rbx, [rbp-0x?]
                if (fpoInfo && l.rmName === (this.is32bit ? 'esp' : 'rsp')) {
                    const ptrSize = this.is32bit ? 4 : 8;
                    const savedRegsSize = fpoInfo.savedRegs.length * ptrSize;
                    const shadowSpace = fpoInfo.hasShadowSpace ? fpoInfo.shadowSize : 0;
                    const totalSaved = savedRegsSize + shadowSpace;
                    const bpReg = this.is32bit ? 'ebp' : 'rbp';
                    
                    let finalOffset;
                    const offset = l.offset || 0;
                    
                    if (offset < totalSaved) {
                        finalOffset = offset - totalSaved;
                        const memNode = new ASTNode('mem');
                        memNode.base = this.regs[bpReg].clone();
                        memNode.offset = finalOffset;
                        this.regs[l.regName] = memNode;
                        this.statements.push(`; FPO: ${l.regName} = ${bpReg} ${finalOffset >= 0 ? '+' : '-'} 0x${Math.abs(finalOffset).toString(16)}`);
                    } else {
                        const localOffset = offset - totalSaved;
                        finalOffset = -(fpoInfo.stackSize - localOffset);
                        const memNode = new ASTNode('mem');
                        memNode.base = this.regs[bpReg].clone();
                        memNode.offset = finalOffset;
                        this.regs[l.regName] = memNode;
                        this.statements.push(`; FPO: ${l.regName} = ${bpReg} - 0x${Math.abs(finalOffset).toString(16)}`);
                    }
                    break;
                }
                
                const memNode = new ASTNode('mem');
                if (l.rmName && this.regs[l.rmName]) {
                    memNode.base = this.regs[l.rmName].clone();
                }
                memNode.offset = l.offset || 0;
                
                this.regs[l.regName] = memNode;
                break;
            }
    
            case 'add':
            case 'sub':
            case 'xor':
            case 'and':
            case 'or': {
                const a = this.decodeModRM(bytes);
                const opMap = { 'add': 'add', 'sub': 'sub', 'xor': 'xor', 'and': 'and', 'or': 'or' };
                const opSymbol = { 'add': '+', 'sub': '-', 'xor': '^', 'and': '&', 'or': '|' }[mnem];

                if (!this.regs[a.regName]) {
                    this.statements.push(`// Unknown ${mnem}: ${inst.text}`);
                    break;
                }
            
                if (!this.regs[a.regName] || !this.regs[a.rmName]) {
                    this.statements.push(`// ${mnem} ${a.regName}, ${a.rmName} (unknown registers, assuming 0)`);
                    this.regs[a.regName] = new ASTNode('const', 0);
                    break;
                }

                if (mnem === 'xor' && a.regName === a.rmName) {
                    this.regs[a.regName] = new ASTNode('const', 0);
                    this.statements.push(`${a.regName} = 0;`);
                    break;
                }

                if (a.isDirect) {
                    if (!this.regs[a.rmName]) {
                        this.statements.push(`// Unknown ${mnem}: ${inst.text}`);
                        break;
                    }
                    this.regs[a.regName] = new ASTNode(
                        opMap[mnem], 
                        null,
                        this.regs[a.regName].clone(),
                        this.regs[a.rmName].clone()
                    );
                    this.statements.push(`${a.regName} = ${this.regs[a.regName].toString()};`);
                } else {
                    const addr = this.resolveAddress(a);
                    const memValue = this.memoryRead(addr, this.getOperandSize(bytes));

                    if (memValue.type === 'const') {
                        const result = new ASTNode(
                            opMap[mnem], 
                            null,
                            this.regs[a.regName].clone(),
                            memValue
                        );
                        this.regs[a.regName] = result;
                        this.statements.push(`${a.regName} = ${result.toString()};`);
                    } else {
                        const result = new ASTNode(
                            opMap[mnem], 
                            null,
                            this.regs[a.regName].clone(),
                            new ASTNode('reg', addr)
                        );
                        this.regs[a.regName] = result;
                        this.statements.push(`${a.regName} = ${this.regs[a.regName].toString()};`);
                    }

                    if (!this.memAccesses) this.memAccesses = {};
                    const baseReg = a.rmName;
                    if (!this.memAccesses[baseReg]) this.memAccesses[baseReg] = [];
                    this.memAccesses[baseReg].push({
                        offset: a.offset,
                        size: this.getOperandSize(bytes),
                        type: mnem,
                        rva: inst.rva
                    });
                }
                break;
            }
            case 'imul': {
                const a = this.decodeModRM(bytes);
                if (!this.regs[a.regName] || !this.regs[a.rmName]) {
                    this.statements.push(`// imul ${a.regName}, ${a.rmName} (cannot emulate)`);
                    break;
                }
                this.regs[a.regName] = new ASTNode(
                    'mul',
                    null,
                    this.regs[a.regName].clone(),
                    this.regs[a.rmName].clone()
                );
                this.statements.push(`${a.regName} = ${this.regs[a.regName].toString()};`);
                break;
            }
            case 'neg': {
                const a = this.decodeModRM(bytes);
                if (!this.regs[a.regName]) {
                    this.statements.push(`// neg ${a.regName} (cannot emulate)`);
                    break;
                }
                this.regs[a.regName] = new ASTNode(
                    'sub',
                    null,
                    new ASTNode('const', 0),
                    this.regs[a.regName].clone()
                );
                this.statements.push(`${a.regName} = ${this.regs[a.regName].toString()};`);
                break;
            }
            case 'not': {
                const a = this.decodeModRM(bytes);
                if (!this.regs[a.regName]) {
                    this.statements.push(`// not ${a.regName} (cannot emulate)`);
                    break;
                }
                this.regs[a.regName] = new ASTNode(
                    'xor',
                    null,
                    this.regs[a.regName].clone(),
                    new ASTNode('const', -1)
                );
                this.statements.push(`${a.regName} = ${this.regs[a.regName].toString()};`);
                break;
            }
            
            case 'push': {
                const fpoInfo = this.getCurrentFPOInfo();
                const regMatch = inst.text && inst.text.match(/push (r?[a-z]+)/i);
                
                if (fpoInfo && regMatch && !regMatch[1].includes('bp')) {
                    fpoInfo.savedRegs.unshift(regMatch[1]);
                    this.statements.push(`; FPO: save ${regMatch[1]} (will restore at epilog)`);
                    this.savedRegs = fpoInfo.savedRegs;
                }
            
                let pVal;
                if (op0 >= 0x50 && op0 <= 0x57) {
                    const regNames = this.is32bit 
                        ? ['eax','ecx','edx','ebx','esp','ebp','esi','edi']
                        : ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'];
                    const regName = regNames[op0 - 0x50];
                    pVal = this.regs[regName];
                } else {
                    const m = this.decodeModRM(bytes);
                    pVal = this.regs[m.regName];
                }
                
                this.stackPush(pVal.clone());
                this.statements.push(`push ${pVal.toString()};`);
                break;
            }  
    
            case 'pop': {
                const fpoInfo = this.getCurrentFPOInfo();
                const targetPop = (op0 >= 0x58 && op0 <= 0x5F)
                    ? (this.is32bit 
                        ? ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][op0 - 0x58]
                        : ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][op0 - 0x58])
                    : this.decodeModRM(bytes).regName;
                    
                if (fpoInfo && fpoInfo.savedRegs.length > 0 && fpoInfo.savedRegs[0] === targetPop) {
                    fpoInfo.savedRegs.shift();
                    this.statements.push(`; FPO: restore ${targetPop}`);
                    this.savedRegs = fpoInfo.savedRegs;
                }
                
                const popped = this.stackPop();
                this.regs[targetPop] = popped.clone();
                this.statements.push(`${targetPop} = ${popped.toString()};`);
                break;
            }
            
            case 'inc':
            case 'dec': {
                const sign = mnem === 'inc' ? 1 : -1;
                const regIdx = op0 >= 0x40 && op0 <= 0x4F ? (op0 & 7) : -1;
                const target = regIdx !== -1 
                    ? (this.is32bit
                        ? ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][regIdx]
                        : ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][regIdx])
                    : this.decodeModRM(bytes).regName;

                if (!this.regs[target]) {
                    this.statements.push(`// Unknown ${mnem}: ${inst.text}`);
                    break;
                }
                
                this.regs[target] = new ASTNode(
                    'add', 
                    null,
                    this.regs[target].clone(),
                    new ASTNode('const', 1)
                );
                this.statements.push(`${target} = ${this.regs[target].toString()};`);
                break;
            }
    
            case 'cmp':
            case 'test': {
                const c = this.decodeModRM(bytes);

                let leftNode, rightNode;

                if (c.isDirect) {
                    leftNode = this.regs[c.regName];
                    rightNode = this.regs[c.rmName];

                    if (!leftNode || !rightNode) {
                        this.flags.lastCompAST = null;
                        this.statements.push(`// cmp ${c.regName}, ${c.rmName} (unknown registers)`);
                        break;
                    }
                } else {
                    const addr = this.resolveAddress(c);
                    const size = this.getOperandSize(bytes);
                    leftNode = this.regs[c.regName];
                    rightNode = this.memoryRead(addr, size);

                    if (!leftNode) {
                        this.flags.lastCompAST = null;
                        this.statements.push(`// cmp ${c.regName}, [${addr}] (unknown register)`);
                        break;
                    }
                }

                const diff = new ASTNode('sub', null, leftNode.clone(), rightNode.clone()).simplify();
                this.flags.lastCompAST = diff;
                const leftStr = leftNode.toString();
                const rightStr = rightNode.toString();

                if (mnem === 'test') {
                    this.statements.push(`// test ${leftStr}, ${rightStr}`);
                    this.flags.lastCompAST = new ASTNode('const', 0);
                } else {
                    this.statements.push(`// cmp ${leftStr}, ${rightStr}`);
                }
                break;
            }
    
            case 'jmp': {
                let targetAddr = 'label_0x...';
                const match = inst.text.match(/0x([0-9a-f]+)/i);
                if (match) {
                    const targetRVA = parseInt(match[1], 16);
                    
                    if (this.functionNames && this.functionNames.has(targetRVA)) {
                        const funcName = this.functionNames.get(targetRVA);
                        this.statements.push(`goto ${funcName}; // jump to exported function`);
                    } else {
                        targetAddr = `label_0x${match[1]}`;
                        this.statements.push(`goto ${targetAddr};`);
                    }
                } else {
                    this.statements.push(`goto ${targetAddr};`);
                }
                break;
            }
            
            case 'jo': case 'jno': case 'js': case 'jns': case 'jz': case 'jnz':
            case 'je': case 'jne': case 'jb': case 'jnb': case 'jae': case 'jbe':
            case 'ja': case 'jl': case 'jnl': case 'jge': case 'jle': case 'jg':
            case 'jp': case 'jnp': case 'jpe': case 'jpo': case 'jcxz': case 'jecxz': case 'jrcxz': {
                if (!this.flags.lastCompAST && mnem !== 'jcxz' && mnem !== 'jecxz' && mnem !== 'jrcxz') {
                    this.statements.push(`// ${mnem} at 0x${inst.rva?.toString(16)} - unknown condition (no previous cmp/test)`);
                    break;
                }

                let targetAddr = 'label';
                const match = inst.text.match(/0x([0-9a-f]+)/i);
                if (match) {
                    const targetRVA = parseInt(match[1], 16);
                    if (this.functionNames && this.functionNames.has(targetRVA)) {
                        targetAddr = this.functionNames.get(targetRVA);
                    } else {
                        targetAddr = `label_0x${match[1]}`;
                    }
                }

                const diff = this.flags.lastCompAST;

                if (mnem === 'jcxz' || mnem === 'jecxz' || mnem === 'jrcxz') {
                    const reg = mnem === 'jrcxz' ? 'rcx' : (mnem === 'jecxz' ? 'ecx' : 'cx');
                    this.statements.push(`if (${reg} == 0) goto ${targetAddr};`);
                    break;
                }

                if (!diff) {
                    this.statements.push(`// ${mnem} ${targetAddr} - condition unknown, assuming always taken`);
                    this.statements.push(`goto ${targetAddr};`);
                    break;
                }

                const diffStr = diff.toString();
                const conditionMap = {
                    'jb': { cond: '<' }, 'jnb': { cond: '>=' }, 'jae': { cond: '>=' },
                    'jbe': { cond: '<=' }, 'ja': { cond: '>' }, 'jl': { cond: '<' },
                    'jnl': { cond: '>=' }, 'jge': { cond: '>=' }, 'jle': { cond: '<=' },
                    'jg': { cond: '>' }, 'jz': { cond: '==' }, 'je': { cond: '==' },
                    'jnz': { cond: '!=' }, 'jne': { cond: '!=' },
                    'jo': { flag: 'OF', flagValue: 1 }, 'jno': { flag: 'OF', flagValue: 0 },
                    'js': { flag: 'SF', flagValue: 1 }, 'jns': { flag: 'SF', flagValue: 0 },
                    'jp': { flag: 'PF', flagValue: 1 }, 'jnp': { flag: 'PF', flagValue: 0 },
                    'jpe': { flag: 'PF', flagValue: 1 }, 'jpo': { flag: 'PF', flagValue: 0 }
                };

                const cond = conditionMap[mnem];

                if (!cond) {
                    this.statements.push(`// ${mnem} ${targetAddr} - unsupported condition`);
                    this.statements.push(`goto ${targetAddr};`);
                    break;
                }

                if (cond.flag) {
                    const flagVar = `flags.${cond.flag}`;
                    this.statements.push(`if (${flagVar} ${cond.flagValue === 1 ? '' : '== 0'}) goto ${targetAddr};`);
                    break;
                }

                if (diff.type === 'const') {
                    const constValue = diff.value;
                    this.statements.push(`if (0x${constValue.toString(16)} ${cond.cond} 0) goto ${targetAddr};`);
                    break;
                }

                if (diff.type === 'sub') {
                    const left = diff.left.toString();
                    const right = diff.right.toString();
                    if (right === '0') {
                        this.statements.push(`if (${left} ${cond.cond} 0) goto ${targetAddr};`);
                    } else {
                        this.statements.push(`if (${left} ${cond.cond} ${right}) goto ${targetAddr};`);
                    }
                    break;
                }

                this.statements.push(`if (${diffStr} ${cond.cond} 0) goto ${targetAddr};`);
                break;
            }
            case 'call': {
                let targetAddr = null;
                let targetName = null;
                
                const directCall = inst.text.match(/call 0x([0-9a-f]+)/i);
                const indirectCall = inst.text.match(/call \[(.*?)\]/i);
                
                if (directCall) {
                    targetAddr = parseInt(directCall[1], 16);
                } else if (indirectCall) {
                    targetName = indirectCall[1];
                }
                
                let funcName = null;
                
                if (targetAddr && this.functionNames && this.functionNames.has(targetAddr)) {
                    funcName = this.functionNames.get(targetAddr);
                }
                
                if (!funcName && targetAddr && this.apiNames && this.apiNames.has(targetAddr)) {
                    funcName = this.apiNames.get(targetAddr);
                }
                
                if (!funcName && targetName) {
                    const cleanName = targetName.replace(/[\[\]]/g, '').split('+')[0];
                    if (this.imports) {
                        for (const imp of this.imports) {
                            for (const func of imp.functions) {
                                if (func.name === cleanName || 
                                    (func.ordinal && func.ordinal.toString() === cleanName)) {
                                    funcName = func.name;
                                    break;
                                }
                            }
                        }
                    }
                }
                
                const args = [];
                const argRegs = ['rcx', 'rdx', 'r8', 'r9'];
                for (const reg of argRegs) {
                    if (this.regs[reg] && this.regs[reg].toString() !== reg) {
                        args.push(this.regs[reg].clone());
                    }
                }
                
                if (!this.is32bit && args.length > 0) {
                    this.statements.push(`sub rsp, 0x20;  // shadow space for call`);
                }
                
                const argsStr = args.map(arg => {
                    let s = arg.toString();
                    if (arg.type === 'const' && typeof arg.value === 'string') return s;
                    if (s.startsWith('[') && s.endsWith(']')) return s;
                    if (arg.type === 'reg' || arg.type === 'const') return s;
                    return `(${s})`;
                }).join(', ');
                
                this.statements.push(`${funcName || `func_0x${(targetAddr || '???').toString(16)}`}(${argsStr});`);
                
                const callNode = new ASTNode('call', funcName || `func_${(targetAddr || '???').toString(16)}`);
                callNode.args = args;
                this.regs.rax = callNode;
                break;
            }
    
            case 'ret': {
                const fpoInfo = this.getCurrentFPOInfo();
                const spReg = this.is32bit ? 'esp' : 'rsp';
                const bpReg = this.is32bit ? 'ebp' : 'rbp';
                
                if (fpoInfo && fpoInfo.savedRegs && fpoInfo.savedRegs.length > 0) {
                    for (let i = fpoInfo.savedRegs.length - 1; i >= 0; i--) {
                        this.statements.push(`    pop ${fpoInfo.savedRegs[i]}                ; restore saved register`);
                    }
                    if (fpoInfo.stackSize > 0) {
                        this.statements.push(`    add ${spReg}, 0x${fpoInfo.stackSize.toString(16)}            ; free stack space`);
                    }
                    this.statements.push(`    pop ${bpReg}                 ; restore frame pointer`);
                } else {
                    this.statements.push(`    leave`);
                }
                this.statements.push(`    return ${this.regs[this.is32bit ? 'eax' : 'rax'].toString()};`);
                break;
            }
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
    
            case 'db': {
                const dbBytes = inst.bytes;
                
                if (dbBytes.length === 2) {
                    const byte1 = dbBytes[0];
                    const byte2 = dbBytes[1];
                    
                    if (byte1 === 0x0b && byte2 >= 0x04 && byte2 <= 0x0f) {
                        const value = (byte2 << 8) | byte1;
                        this.statements.push(`// constant: 0x${value.toString(16)} (possible jump table entry)`);
                        break;
                    }
                    
                    if ((byte1 === 0x0d || byte1 === 0x0e || byte1 === 0x0f) && byte2 >= 0x00 && byte2 <= 0x0f) {
                        const value = (byte2 << 8) | byte1;
                        this.statements.push(`// constant: 0x${value.toString(16)}`);
                        break;
                    }
                    
                    if (byte1 <= 0x20 && byte2 <= 0x20) {
                        this.statements.push(`// padding: 0x${byte1.toString(16)}, 0x${byte2.toString(16)}`);
                        break;
                    }
                }
                
                if (dbBytes.length >= 4) {
                    const value = dbBytes[0] | (dbBytes[1] << 8) | (dbBytes[2] << 16) | (dbBytes[3] << 24);
                    this.statements.push(`// dword constant: 0x${value.toString(16)}`);
                    break;
                }
                
                const hexBytes = Array.from(dbBytes).map(b => '0x' + b.toString(16)).join(', ');
                this.statements.push(`// db ${hexBytes} (raw data)`);
                break;
            }
            case 'undefined': {
                const opcode = bytes[0];
                const secondByte = bytes[1] || 0;
                
                this.statements.push(`// ⚠️ UNDEFINED INSTRUCTION at 0x${inst.rva?.toString(16) || '?'}`);
                this.statements.push(`//    bytes: ${Array.from(bytes).map(b => '0x' + b.toString(16)).join(' ')}`);
                this.statements.push(`//    mnemonic: ${mnem}, text: ${inst.text}`);
                
                if (bytes[0] === 0x0F && bytes[1] === 0x0B) {
                    this.statements.push(`//    This is UD2 (undefined instruction) - used for debugging`);
                } else if (bytes[0] === 0x0F && bytes[1] === 0x31) {
                    this.statements.push(`//    This is RDTSC (read timestamp counter) - returns CPU cycles`);
                    this.regs.rax = { v: Date.now(), l: 'timestamp_low' };
                    this.regs.rdx = { v: 0, l: 'timestamp_high' };
                } else if (bytes[0] === 0x0F && bytes[1] === 0xA2) {
                    this.statements.push(`//    This is CPUID - returns processor info`);
                    this.regs.rax = { v: 0, l: '"GenuineIntel"' };
                } else if (bytes[0] === 0x0F && bytes[1] === 0x05) {
                    this.statements.push(`//    This is SYSCALL - system call (Windows API transition)`);
                } else if (bytes[0] === 0x0F && bytes[1] === 0x34) {
                    this.statements.push(`//    This is SYSENTER - fast system call`);
                } else if (bytes[0] === 0xCD && bytes[1] === 0x2E) {
                    this.statements.push(`//    This is INT 2E - old style system call (Windows 9x/NT)`);
                } else if (bytes[0] === 0xCC) {
                    this.statements.push(`//    This is INT 3 breakpoint`);
                } else if (bytes[0] === 0x0F && (bytes[1] === 0x0F || bytes[1] === 0x1F)) {
                    this.statements.push(`//    This is a multi-byte NOP (padding)`);
                } else {
                    const opcodeInfo = this.getOpcodeInfo(bytes);
                    if (opcodeInfo) {
                        this.statements.push(`//    Possibly: ${opcodeInfo}`);
                    }
                }
                break;
            }
            default:
                if (mnem !== 'int3' && mnem !== 'db' && mnem !== '???') {
                    this.statements.push(`// C++ JSCPU Decomp Warning: Unknown operation ${mnem}`);
                }
                break;
        }
    }
}

class FPODeoptimizer {
    constructor(instructions, bytes, imageBase = 0, is32bit = false) {
        this.instructions = instructions;
        this.bytes = bytes;
        this.imageBase = imageBase;
        this.is32bit = is32bit;
        this.deoptimized = [];
        this.functions = [];
        this.maxDepth = 50;
    }

    deoptimize() {
        this.analyzeFunctionBoundaries();
        
        for (const func of this.functions) {
            if (this.isDataSection(func)) {
                const decompiled = this.deoptimizeDataSection(func);
                this.deoptimized.push(...decompiled);
            } else if (this.isFPOFunction(func)) {
                const decompiled = this.deoptimizeFPOFunction(func);
                this.deoptimized.push(...decompiled);
            } else {
                const decompiled = this.keepAsIs(func);
                this.deoptimized.push(...decompiled);
            }
        }
        
        return this.deoptimized;
    }

    isNonVolatile(reg) {
        const nonVolatile64 = ['rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'];
        const nonVolatile32 = ['ebx', 'esi', 'edi'];
        return this.is32bit 
            ? nonVolatile32.includes(reg.toLowerCase())
            : nonVolatile64.includes(reg.toLowerCase());
    }

    keepAsIs(func) {
        const lines = [];
        const typeLabel = func.type === 'std' ? 'Standard function' :
                         func.type === 'std32' ? '32-bit standard function' :
                         func.type === 'fpo32' ? '32-bit FPO function' :
                         func.type === 'hotpatch' ? 'Hotpatch function' :
                         'Function';
        
        lines.push(`// ${typeLabel} at 0x${func.start.toString(16)}`);
        for (const inst of func.insts) {
            lines.push(`    ${inst.text}`);
        }
        lines.push(``);
        return lines;
    }

    isFPOEpilogue(inst, savedRegs) {
        const spReg = this.is32bit ? 'esp' : 'rsp';
        if (inst.mnemonic === 'add' && inst.text.includes(spReg)) {
            return true;
        }
        if (inst.mnemonic === 'pop' && savedRegs.some(r => inst.text.includes(r))) {
            return true;
        }
        return false;
    }

    isFPOInstruction(inst, savedRegs) {
        if (inst.mnemonic === 'push' && savedRegs.some(r => inst.text.includes(r))) {
            return true;
        }
        const spReg = this.is32bit ? 'esp' : 'rsp';
        if (inst.mnemonic === 'sub' && inst.text.includes(spReg)) {
            return true;
        }
        return false;
    }

    isDataSection(func) {
        if (!func.insts || func.insts.length === 0) return false;
        
        let dbCount = 0;
        let nonsenseCount = 0;
        let patternCount = 0;
        
        for (const inst of func.insts) {
            if (inst.mnemonic === 'db') {
                dbCount++;
            }
            
            if (inst.text && inst.text.match(/rax = \(\(rax \+ rbx\) \+ 0\)/)) {
                patternCount++;
            }
            
            const parenCount = (inst.text?.match(/\(/g) || []).length;
            if (parenCount > 10) {
                nonsenseCount++;
            }
        }
        
        const dbRatio = dbCount / func.insts.length;
        const patternRatio = patternCount / func.insts.length;
        const nonsenseRatio = nonsenseCount / func.insts.length;
        
        if (patternRatio > 0.3 || dbRatio > 0.5 || nonsenseRatio > 0.3) {
            return true;
        }
        
        return false;
    }

    deoptimizeDataSection(func) {
        const lines = [];
        const startAddr = this.imageBase + func.start;
        
        lines.push(`// ============================================================`);
        lines.push(`// DATA SECTION at 0x${func.start.toString(16)} (virtual: 0x${startAddr.toString(16)})`);
        lines.push(`// ============================================================`);
        
        const bytes = [];
        let currentBytes = [];
        
        for (const inst of func.insts) {
            if (inst.mnemonic === 'db' && inst.bytes) {
                for (const b of inst.bytes) {
                    currentBytes.push(b);
                    if (currentBytes.length >= 16) {
                        bytes.push([...currentBytes]);
                        currentBytes = [];
                    }
                }
            } else if (inst.mnemonic !== 'db') {
                if (currentBytes.length > 0) {
                    bytes.push([...currentBytes]);
                    currentBytes = [];
                }
                lines.push(`    ${inst.text}`);
            }
        }
        
        if (currentBytes.length > 0) {
            bytes.push([...currentBytes]);
        }
        
        if (bytes.length > 0) {
            lines.push(`    // Hex dump:`);
            for (let i = 0; i < bytes.length; i++) {
                const hex = bytes[i].map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ');
                const offset = i * 16;
                lines.push(`    // 0x${offset.toString(16)}: ${hex}`);
            }
        }
        
        const strings = this.extractStringsFromBytes(func);
        if (strings.length > 0) {
            lines.push(`    // Possible strings:`);
            for (const str of strings) {
                lines.push(`    //   "${str}"`);
            }
        }
        
        lines.push(``);
        return lines;
    }

    extractStringsFromBytes(func) {
        const strings = [];
        let currentStr = '';
        let isUnicode = false;
        
        for (const inst of func.insts) {
            if (inst.mnemonic === 'db' && inst.bytes) {
                for (let i = 0; i < inst.bytes.length; i++) {
                    const b = inst.bytes[i];
                    
                    // ASCII рядок
                    if (b >= 0x20 && b <= 0x7E) {
                        if (!isUnicode) {
                            currentStr += String.fromCharCode(b);
                        }
                    } 
                    // Unicode (два байти)
                    else if (i + 1 < inst.bytes.length && b === 0x00 && inst.bytes[i+1] >= 0x20 && inst.bytes[i+1] <= 0x7E) {
                        if (currentStr.length > 0 && !isUnicode) {
                            if (currentStr.length >= 4) strings.push(currentStr);
                            currentStr = '';
                        }
                        isUnicode = true;
                        currentStr += String.fromCharCode(inst.bytes[i+1]);
                        i++;
                    }
                    else {
                        if (currentStr.length >= 4) {
                            strings.push(currentStr);
                        }
                        currentStr = '';
                        isUnicode = false;
                    }
                }
            }
        }
        
        if (currentStr.length >= 4) {
            strings.push(currentStr);
        }
        
        return strings;
    }

    isFPOFunction(func) {
        if (!func.insts || func.insts.length === 0) return false;
        
        let hasPushRbp = false;
        let hasMovRbpRsp = false;
        let hasPushNonVolatile = false;
        let hasSubRsp = false;
        
        for (let i = 0; i < Math.min(10, func.insts.length); i++) {
            const inst = func.insts[i];
            if (!inst) continue;
            
            const rbpName = this.is32bit ? 'ebp' : 'rbp';
            const rspName = this.is32bit ? 'esp' : 'rsp';
            
            if (inst.mnemonic === 'push' && inst.text.includes(rbpName)) {
                hasPushRbp = true;
            }
            if (inst.mnemonic === 'mov' && inst.text.includes(rbpName) && inst.text.includes(rspName)) {
                hasMovRbpRsp = true;
            }
            
            const nonVolatile32 = ['ebx', 'esi', 'edi'];
            const nonVolatile64 = ['rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'];
            const nonVolatile = this.is32bit ? nonVolatile32 : nonVolatile64;
            
            if (inst.mnemonic === 'push' && nonVolatile.some(r => inst.text.includes(r))) {
                hasPushNonVolatile = true;
            }
            if (inst.mnemonic === 'sub' && inst.text.includes(rspName)) {
                hasSubRsp = true;
            }
        }
        
        return !hasPushRbp && !hasMovRbpRsp && (hasPushNonVolatile || hasSubRsp);
    }

    analyzeFPOFunction(func) {
        const savedRegs = [];
        let stackFrameSize = 0;
        let hasSEH = false;
        let hasAlloca = false;
        let isDataOnly = true;
        
        for (let i = 0; i < func.insts.length; i++) {
            const inst = func.insts[i];
            
            if (inst.mnemonic === 'db') {
                continue;
            }
            
            isDataOnly = false;
            
            const rbpName = this.is32bit ? 'ebp' : 'rbp';
            const nonVolatile32 = ['ebx', 'esi', 'edi'];
            const nonVolatile64 = ['rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'];
            const nonVolatile = this.is32bit ? nonVolatile32 : nonVolatile64;
            
            if (inst.mnemonic === 'push' && !inst.text.includes(rbpName)) {
                const regMatch = inst.text.match(/push (r?[a-z0-9]+)/i);
                if (regMatch && nonVolatile.includes(regMatch[1].toLowerCase())) {
                    savedRegs.push(regMatch[1]);
                }
            }

            const spName = this.is32bit ? 'esp' : 'rsp';
            if (inst.mnemonic === 'sub' && inst.text.includes(spName)) {
                const sizeMatch = inst.text.match(/0x([0-9a-f]+)/i);
                if (sizeMatch) {
                    const size = parseInt(sizeMatch[1], 16);
                    if (size > 0x1000) {
                        hasAlloca = true;
                    }
                    stackFrameSize = size;
                }
            }
            
            if (inst.text && (inst.text.includes('___chkstk') || 
                inst.text.includes('__alloca') ||
                inst.text.includes('_alloca'))) {
                hasAlloca = true;
            }
            
            if (inst.text && (inst.text.includes('__C_specific_handler') || 
                inst.text.includes('_except_handler') ||
                inst.text.includes('GS_') ||
                inst.text.includes('__security_check_cookie'))) {
                hasSEH = true;
            }
        }
        
        if (isDataOnly) {
            return { savedRegs: [], stackFrameSize: 0, hasSEH: false, hasAlloca: false, isData: true };
        }
        
        return { savedRegs, stackFrameSize, hasSEH, hasAlloca, isData: false };
    }

    deoptimizeFPOFunction(func) {
        const lines = [];
        const analysis = this.analyzeFPOFunction(func);
        
        if (analysis.isData) {
            return this.deoptimizeDataSection(func);
        }
        
        const { savedRegs, stackFrameSize, hasSEH, hasAlloca } = analysis;
        const ptrSize = this.is32bit ? 4 : 8;
        const savedRegsSize = savedRegs.length * ptrSize;
        const bpReg = this.is32bit ? 'ebp' : 'rbp';
        const spReg = this.is32bit ? 'esp' : 'rsp';
        
        if (hasSEH || hasAlloca) {
            lines.push(`// ${hasSEH ? 'SEH handler' : 'alloca'} present - FPO cannot be applied`);
            return this.keepAsIs(func);
        }
        
        lines.push(`// === DEOPTIMIZED FPO FUNCTION ===`);
        lines.push(`// Original: /O2 (FPO) - no ${bpReg} frame`);
        lines.push(`// Platform: ${this.is32bit ? '32-bit (x86)' : '64-bit (x64)'}`);
        lines.push(`// Saved registers: ${savedRegs.join(', ')}`);
        lines.push(`// Stack frame size: 0x${stackFrameSize.toString(16)}`);
        lines.push(``);
        
        lines.push(`push ${bpReg}                     ; standard prologue`);
        lines.push(`mov  ${bpReg}, ${spReg}`);
        
        for (const reg of savedRegs) {
            lines.push(`push ${reg}                     ; save non-volatile`);
        }
        
        if (stackFrameSize > 0) {
            lines.push(`sub  ${spReg}, 0x${stackFrameSize.toString(16)}     ; allocate locals`);
        }
        
        lines.push(``);
        lines.push(`    ; === TRANSFORMED INSTRUCTIONS ===`);
        
        let hasTransformed = false;
        for (const inst of func.insts) {
            if (this.isFPOEpilogue(inst, savedRegs)) continue;
            if (this.isFPOInstruction(inst, savedRegs)) continue;
            if (inst.mnemonic === 'db') {
                continue;
            }
            
            let transformed = this.transformInstruction(inst, savedRegs, stackFrameSize, savedRegsSize);
            transformed = this.simplifyExpression(transformed);
            lines.push(`    ${transformed}`);
            hasTransformed = true;
        }
        
        if (!hasTransformed) {
            lines.push(`    // No instructions transformed (possibly data only)`);
        }
        
        lines.push(``);
        lines.push(`    ; === STANDARD EPILOGUE ===`);
        lines.push(`leave                          ; mov ${spReg}, ${bpReg}; pop ${bpReg}`);
        lines.push(`ret`);
        
        return lines;
    }

    transformInstruction(inst, savedRegs, stackFrameSize, savedRegsSize) {
        let asm = inst.text;
        const ptrSize = this.is32bit ? 4 : 8;
        const spReg = this.is32bit ? 'esp' : 'rsp';
        const bpReg = this.is32bit ? 'ebp' : 'rbp';
        
        if (asm.length > 500 || (asm.match(/\(/g) || []).length > 20) {
            return `// Complex expression (${asm.length} chars) - original: ${asm.substring(0, 100)}...`;
        }
        
        const stackPattern = new RegExp(`\\[${spReg}([+-]0x[0-9a-f]+)\\]`, 'gi');
        let match;
        let lastIndex = 0;
        let result = '';
        
        while ((match = stackPattern.exec(asm)) !== null) {
            const before = asm.substring(lastIndex, match.index);
            const offsetStr = match[1];
            let offset = parseInt(offsetStr, 16);
            const isNegative = offsetStr.startsWith('-');
            if (isNegative) offset = -offset;
            
            let newOffset;
            const returnAddrSize = ptrSize;
            
            if (offset < savedRegsSize) {
                newOffset = offset - savedRegsSize - returnAddrSize;
            } else if (offset < savedRegsSize + stackFrameSize) {
                const localOffset = offset - savedRegsSize;
                newOffset = -(stackFrameSize - localOffset);
            } else {
                const argOffset = offset - savedRegsSize - stackFrameSize;
                newOffset = 0x10 + argOffset;
            }
            
            const sign = newOffset >= 0 ? '+' : '-';
            const absOffset = Math.abs(newOffset);
            const newRef = `[${bpReg}${sign}0x${absOffset.toString(16)}]`;
            result += before + newRef;
            lastIndex = match.index + match[0].length;
        }
        
        result += asm.substring(lastIndex);
        result = result.replace(new RegExp(spReg + '(?![a-z])', 'gi'), bpReg);
        
        const leaMatch = result.match(/lea ([^,]+), \[([^\]]+)\]/i);
        if (leaMatch && leaMatch[2] === bpReg) {
            const dest = leaMatch[1];
            result = `mov ${dest}, ${bpReg}  ; simplified lea`;
        }
        
        return result;
    }

    simplifyExpression(expr, depth = 0) {
        if (depth > this.maxDepth) {
            return `/* expression too deep (depth ${depth}) */`;
        }
        
        // Спрощення: (X + 0) -> X
        expr = expr.replace(/\(\s*([^+\-*/]+)\s*\+\s*0\s*\)/g, '$1');
        expr = expr.replace(/\(\s*0\s*\+\s*([^+\-*/]+)\s*\)/g, '$1');
        
        // Спрощення: (X - 0) -> X
        expr = expr.replace(/\(\s*([^+\-*/]+)\s*-\s*0\s*\)/g, '$1');
        
        // Спрощення: (0 - X) -> -X
        expr = expr.replace(/\(\s*0\s*-\s*([^+\-*/]+)\s*\)/g, '-$1');
        
        // Спрощення: ((X + Y) + Z) -> (X + Y + Z)
        expr = expr.replace(/\(\(([^()]+)\s*\+\s*([^()]+)\)\s*\+\s*([^()]+)\)/g, '($1 + $2 + $3)');
        
        // Спрощення: (X & X) -> X
        expr = expr.replace(/\(\s*([^&]+)\s*&\s*\1\s*\)/g, '$1');
        
        // Спрощення: (X ^ X) -> 0
        expr = expr.replace(/\(\s*([^^]+)\s*\^\s*\1\s*\)/g, '0');
        
        // Спрощення: (X | X) -> X
        expr = expr.replace(/\(\s*([^|]+)\s*\|\s*\1\s*\)/g, '$1');
        
        return expr;
    }

    isFPOEpilogue(inst, savedRegs) {
        const spReg = this.is32bit ? 'esp' : 'rsp';
        if (inst.mnemonic === 'add' && inst.text.includes(spReg)) {
            return true;
        }
        if (inst.mnemonic === 'pop' && savedRegs.some(r => inst.text.includes(r))) {
            return true;
        }
        return false;
    }

    isFPOInstruction(inst, savedRegs) {
        if (inst.mnemonic === 'push' && savedRegs.some(r => inst.text.includes(r))) {
            return true;
        }
        const spReg = this.is32bit ? 'esp' : 'rsp';
        if (inst.mnemonic === 'sub' && inst.text.includes(spReg)) {
            return true;
        }
        return false;
    }

    isNonVolatile(reg) {
        const nonVolatile64 = ['rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'];
        const nonVolatile32 = ['ebx', 'esi', 'edi'];
        return this.is32bit 
            ? nonVolatile32.includes(reg.toLowerCase())
            : nonVolatile64.includes(reg.toLowerCase());
    }

    keepAsIs(func) {
        const lines = [];
        
        if (func.type === 'data') {
            lines.push(`// ============================================================`);
            lines.push(`// DATA SECTION at 0x${func.start.toString(16)}`);
            lines.push(`// ============================================================`);
            
            const bytes = [];
            for (const inst of func.insts) {
                if (inst.bytes) {
                    for (const b of inst.bytes) {
                        bytes.push(b);
                    }
                }
            }
            
            if (bytes.length > 0) {
                lines.push(`    // Hex dump (first ${Math.min(256, bytes.length)} bytes):`);
                for (let i = 0; i < Math.min(256, bytes.length); i += 16) {
                    const hex = bytes.slice(i, i + 16).map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ');
                    lines.push(`    // 0x${i.toString(16)}: ${hex}`);
                }
            }
            
            const strings = this.extractStringsFromBytes(func);
            if (strings.length > 0) {
                lines.push(`    // Strings found:`);
                for (const str of strings) {
                    lines.push(`    //   "${str}"`);
                }
            }
            
            lines.push(``);
            return lines;
        }
        
        const typeLabel = func.type === 'std' ? 'Standard function' :
                         func.type === 'std32' ? '32-bit standard function' :
                         func.type === 'fpo32' ? '32-bit FPO function' :
                         func.type === 'hotpatch' ? 'Hotpatch function' :
                         func.type === 'naked' ? 'Naked function' :
                         'Function';
        
        lines.push(`// ${typeLabel} at 0x${func.start.toString(16)}`);
        for (const inst of func.insts) {
            lines.push(`    ${inst.text}`);
        }
        lines.push(``);
        return lines;
    }

    analyzeInstructionSignal(inst) {
        let codeScore = 0;
        let dataScore = 0;

        if (!inst) return { codeScore: 0, dataScore: 1 };

        const text = inst.text || "";

        if (inst.mnemonic === 'call') codeScore += 5;
        if (inst.mnemonic === 'ret') codeScore += 5;
        if (inst.mnemonic.startsWith('j')) codeScore += 4;
        if (inst.mnemonic === 'mov' || inst.mnemonic === 'add' || inst.mnemonic === 'sub')
            codeScore += 2;
        if (text.includes('[')) codeScore += 2;
        if (text.includes('rbp') && text.includes('rsp')) codeScore += 4;
        if (inst.mnemonic === 'push' && text.includes('rbp')) codeScore += 4;
        if (text.includes('rsp') || text.includes('esp')) codeScore += 2;
        if (inst.mnemonic === 'db') dataScore += 5;
        if (text.length > 200) dataScore += 3;
        const weirdOps = (text.match(/[\^\|\&]/g) || []).length;
        if (weirdOps > 5) dataScore += 2;
        
        return { codeScore, dataScore };
    }

    analyzeFunctionBoundaries() {
        let currentFunc = null;
        
        for (let i = 0; i < this.instructions.length; i++) {
            const inst = this.instructions[i];
            if (!inst) continue;
            
            const rbpName = this.is32bit ? 'ebp' : 'rbp';
            const rspName = this.is32bit ? 'esp' : 'rsp';
            
            let isNonsenseData = false;
            if (inst.text) {
                const addCount = (inst.text.match(/\+/g) || []).length;
                const parenCount = (inst.text.match(/\(/g) || []).length;
                const hasPopVal = inst.text.includes('pop_val_');
                const hasDeepRax = inst.text.match(/rax = \(\(\(\(\(\(\(\(/);
                const isRaxAddRbx = inst.text.match(/rax = \(\(rax \+ rbx\) \+ 0\)/);
                
                if (addCount > 10 || parenCount > 15 || hasPopVal || hasDeepRax || isRaxAddRbx) {
                    isNonsenseData = true;
                }
            }
            
            if (isNonsenseData) {
                if (!currentFunc) {
                    currentFunc = { 
                        start: i, 
                        insts: [], 
                        type: 'data', 
                        is32bit: this.is32bit,
                        isDataSection: true
                    };
                    this.functions.push(currentFunc);
                }
                if (currentFunc) {
                    currentFunc.insts.push(inst);
                }
                continue;
            }
            
            if (currentFunc && currentFunc.type === 'data') {
                const isRealCode = (inst.mnemonic === 'push' && inst.text.includes(rbpName)) ||
                                   (inst.mnemonic === 'mov' && inst.text.includes(rbpName) && inst.text.includes(rspName)) ||
                                   inst.mnemonic === 'ret' ||
                                   inst.mnemonic === 'call';
                
                if (isRealCode) {
                    currentFunc.end = i - 1;
                    currentFunc = null;
                } else {
                    currentFunc.insts.push(inst);
                    continue;
                }
            }
            
            const isHotpatch = inst.bytes && inst.bytes.length >= 2 && 
                               inst.bytes[0] === 0x8b && inst.bytes[1] === 0xff;
            const isPushReg = inst.mnemonic === 'push' && 
                              (inst.text.includes('rbx') || inst.text.includes('rsi') || 
                               inst.text.includes('rdi') || inst.text.includes('r12') ||
                               inst.text.includes('r13') || inst.text.includes('r14') ||
                               inst.text.includes('r15'));
            const isStdPrologue = inst.mnemonic === 'push' && 
                                  (inst.text.includes(rbpName) || inst.text.includes('ebp'));
            const isMovRbpRsp = inst.mnemonic === 'mov' && 
                                inst.text.includes(rbpName) && inst.text.includes(rspName);
            
            const is32bitFpo = inst.mnemonic === 'push' && 
                   (inst.text.includes('ebx') || inst.text.includes('esi') || 
                    inst.text.includes('edi'));
            const is32bitPrologue = inst.mnemonic === 'push' && inst.text.includes('ebp');
            
            if (inst.mnemonic === 'db') {
                if (currentFunc) {
                    currentFunc.insts.push(inst);
                }
                continue;
            }
    
            if (is32bitPrologue) {
                currentFunc = { start: i, insts: [], type: 'std32', is32bit: true, savedRegs: [] };
                this.functions.push(currentFunc);
            } 
            else if (is32bitFpo && !currentFunc) {
                currentFunc = { start: i, insts: [], type: 'fpo32', is32bit: true, savedRegs: [] };
                this.functions.push(currentFunc);
            }
            else if (isMovRbpRsp && !currentFunc) {
                currentFunc = { 
                    start: i, 
                    insts: [], 
                    type: 'fpo_with_rbp', 
                    savedRegs: [],
                    stackSize: 0,
                    is32bit: false
                };
                this.functions.push(currentFunc);
            }
            else if (isStdPrologue) {
                currentFunc = { start: i, insts: [], type: 'std', savedRegs: [], is32bit: false };
                this.functions.push(currentFunc);
            } 
            else if (isHotpatch && i + 1 < this.instructions.length) {
                const next = this.instructions[i + 1];
                if (next.mnemonic === 'push' && next.text.includes(rbpName)) {
                    currentFunc = { start: i, insts: [], type: 'hotpatch', savedRegs: [], is32bit: false };
                    this.functions.push(currentFunc);
                    i++;
                }
            }
            else if (isPushReg && i + 1 < this.instructions.length && !currentFunc) {
                const next = this.instructions[i + 1];
                if (next.mnemonic === 'push' || next.mnemonic === 'sub') {
                    currentFunc = { 
                        start: i, 
                        insts: [], 
                        type: 'fpo', 
                        savedRegs: [],
                        stackSize: 0,
                        is32bit: false
                    };
                    this.functions.push(currentFunc);
                }
            }
            else if (!currentFunc && inst.mnemonic !== 'db') {
                currentFunc = { 
                    start: i, 
                    insts: [], 
                    type: 'naked', 
                    savedRegs: [],
                    stackSize: 0,
                    is32bit: this.is32bit
                };
                this.functions.push(currentFunc);
            }
    
            if (currentFunc && currentFunc.type !== 'data') {
                if (inst.text && (inst.text.includes('__C_specific_handler') || 
                    inst.text.includes('_except_handler'))) {
                    currentFunc.hasSEH = true;
                }
    
                if (inst.mnemonic === 'sub' && inst.text.includes(rspName)) {
                    const sizeMatch = inst.text.match(/0x([0-9a-f]+)/i);
                    if (sizeMatch && currentFunc) {
                        const size = parseInt(sizeMatch[1], 16);
                        if (size === 0x20 || size === 0x28 || size === 0x30) {
                            currentFunc.hasShadowSpace = true;
                            currentFunc.shadowSize = size;
                        }
                        currentFunc.stackSize = size;
                    }
                }
                
                currentFunc.insts.push(inst);
                
                if (inst.mnemonic === 'ret' || 
                    (inst.mnemonic === 'jmp' && !inst.text.includes('call'))) {
                    currentFunc.end = i;
                    currentFunc = null;
                }
            }
        }
        
        if (currentFunc && currentFunc.type === 'data') {
            currentFunc.end = this.instructions.length - 1;
        }
        
        const stdCount = this.functions.filter(f => f.type === 'std' || f.type === 'std32').length;
        const fpoCount = this.functions.filter(f => f.type === 'fpo' || f.type === 'fpo32' || f.type === 'fpo_with_rbp').length;
        const hotpatchCount = this.functions.filter(f => f.type === 'hotpatch').length;
        const nakedCount = this.functions.filter(f => f.type === 'naked').length;
        const dataCount = this.functions.filter(f => f.type === 'data').length;
        
        console.log(`Found ${this.functions.length} functions (std: ${stdCount}, FPO: ${fpoCount}, hotpatch: ${hotpatchCount}, naked: ${nakedCount}, data: ${dataCount})`);
        
        return this.functions;
    }
    
    isLargeNonsenseBlock(func) {
        if (!func.insts || func.insts.length < 5) return false;
        
        let nonsenseCount = 0;
        let totalInsts = 0;
        
        for (const inst of func.insts) {
            totalInsts++;
            
            if (inst.mnemonic === 'db') {
                nonsenseCount++;
                continue;
            }
            
            if (inst.text) {
                const addCount = (inst.text.match(/\+/g) || []).length;
                if (addCount > 10) {
                    nonsenseCount++;
                    continue;
                }
                
                const parenCount = (inst.text.match(/\(/g) || []).length;
                if (parenCount > 10) {
                    nonsenseCount++;
                    continue;
                }
                
                if (inst.text.includes('pop_val_')) {
                    nonsenseCount++;
                    continue;
                }
                
                if (inst.text.match(/rax = \(\(rax \+ rbx\) \+ 0\)/)) {
                    nonsenseCount++;
                    continue;
                }
            }
        }
        
        const nonsenseRatio = totalInsts > 0 ? nonsenseCount / totalInsts : 0;
        
        return nonsenseRatio > 0.4;
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

const GUECMan = new GUECManager();
