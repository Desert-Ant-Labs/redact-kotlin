package ai.desertant.redact

/**
 * High-precision deterministic recognizers (regex + checksums), a faithful port
 * of `redact_training.deterministic` (kept in span-for-span parity with the
 * Python / JS / Swift runtimes). These *own* structured labels where a checksum
 * or distinctive format beats the small neural model.
 */
internal object Deterministic {
    val owned = setOf(
        "EMAIL", "URL", "IP_ADDRESS", "CREDIT_CARD", "SSN", "BANK_ACCOUNT",
        "ROUTING_NUMBER", "TAX_ID", "GOVERNMENT_ID", "PASSPORT", "DRIVERS_LICENSE", "IMEI",
    )

    // Java regex: (?i) case-insensitive, (?-i:) scoped-off, (?U) unicode \b/\w.
    private fun rx(p: String) = Regex(p)

    private val emailRe = rx("""(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])([\p{L}\p{N}.!#$%&'*+/=?^`{|}~-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})(?![A-Za-z0-9-])""")
    private val urlRe = rx("""(?i)\b((?:https?://|ftp://|www\.)[^\s<>()\[\]{}"']{3,})""")
    private val ipv4Re = rx("""(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)""")
    private val ipv6Re = rx("""(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])""")
    private val macRe = rx("""(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])""")
    private val ccRe = rx("""(?<!\d)(?:\d[ -]?){13,19}(?!\d)""")
    private val ibanRe = rx("""(?i)\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b""")
    private val bicRe = rx("""\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b""")
    private val ssnRe = rx("""(?<!\d)(\d{3})[- ](\d{2})[- ](\d{4})(?!\d)""")
    private val routingRe = rx("""(?<!\d)\d{9}(?!\d)""")
    private val esDniRe = rx("""(?i)(?<![A-Z0-9])(?:\d{8}|[XYZ]\d{7})[A-Z](?![A-Z0-9])""")
    private val natIdRe = rx("""(?<![A-Za-z0-9])\d[\d .\-]{7,17}\d(?![A-Za-z0-9])""")
    private val itCfRe = rx("""(?i)(?<![A-Za-z0-9])[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z](?![A-Za-z0-9])""")
    private val fiHetuRe = rx("""(?<![A-Za-z0-9])\d{6}[-+A-F]\d{3}[0-9A-Y](?![A-Za-z0-9])""")
    private val dkCprRe = rx("""(?<!\d)\d{6}[- ]?\d{4}(?!\d)""")
    private val vatRe = rx("""(?<![A-Za-z0-9])(AT|BE|BG|CY|CZ|DE|DK|EE|EL|GR|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)\s?([0-9A-Za-z]{5,14})(?![A-Za-z0-9])""")
    private val imeiRe = rx("""(?<!\d)\d{15}(?!\d)""")
    private val sePnRe = rx("""(?<!\d)((?:\d{2})?\d{6})[-+](\d{4})(?!\d)""")
    private val passportValRe = rx("""(?<![A-Za-z0-9])[A-Z0-9]{6,9}(?![A-Za-z0-9])""")
    private val ppsRe = rx("""(?<![A-Za-z0-9])\d{7}[A-Za-z]{1,2}(?![A-Za-z0-9])""")
    private val plDlRe = rx("""(?<![0-9/])\d{5}/\d{2}/\d{4,7}(?![0-9/])""")
    private val contextDigitRe = rx("""(?<![A-Za-z0-9])\d{7,12}(?![A-Za-z0-9])""")
    private val intlPhoneRe = rx("""(?<!\w)\+\d{1,3}[ .-]?(?:\(?\d{1,5}\)?[ .-]?){1,5}\d{2,5}(?!\w)""")
    private val genericPhoneRe = rx("""(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{2,5}\)?[ .-]?){2,5}\d{2,5}(?!\w)""")
    private val dlKwRe = rx("""(?i)(?U)\b(driving licen[cs]e|driver'?s? licen[cs]e|licence number|permis de conduire|permis de conduite|f[uü]hrerschein|fahrerlaubnis(?:nummer)?|patente(?: di guida)?|numero patente|prawo jazdy|rijbewijs(?:nummer)?|(?:carn[eé]|permiso) de conducir|carta de condu[cç][aã]o|k[oö]rkort(?:snummer)?|k[oø]rekort|ajokortti|vezet[oő]i enged[eé]ly|[rř]idi[cč]sk\w* pr[uů]kaz\w*|vodi[cč]sk\w* preukaz\w*|permis de conducere|voza[cč]k[au] dozvol[ae]|vozni[sš]ko dovoljenje|vairuotojo pa[zž]ym[eė]jimas|vad[iī]t[aā]ja apliec[iī]ba|juhiluba|licenzja tas-sewqan)(?i:[\s.:\-]*(?:nr|no|nummer|number|num[eé]ro|n[°º])\.?)?(?-i:[^A-Z0-9\n]{0,14}?([A-Z0-9](?:[A-Z0-9]|[ .\-/](?=[A-Z0-9])){4,24}))""")
    private val docIdKwRe = rx("""(?i)\b(passport|passeport|reisepass|pasaporte|passaporto|paspoort|national id|identity card|id card|identity number|identification number|id number|id no|personalausweis|ausweisnummer|ausweis|carte d.identit[eé]|documento de identidad|documento di identit[aà]|carta d.identit[aà]|identiteitskaart|n[uú]mero de identificaci[oó]n|de identifica[cç][aã]o|c[eé]dula)(?-i:[^A-Z0-9\n]{0,18}?([A-Z0-9](?:[A-Z0-9]|[ .\-/](?=[A-Z0-9])){4,44}))""")
    private val passportKwRe = rx("""(?i)^(passport|passeport|reisepass|pasaporte|passaporto|paspoort)""")

    private val ipCtx = rx("""(?i)\b(?:ip|ipv4|ipv6|address|addr|host|server|node|endpoint|cidr)\b|地址""")
    private val routingCtx = rx("""(?i)\b(?:routing|aba|bank|wire|ach)\b""")
    private val ssnCtx = rx("""(?i)\b(?:ssn|social security|social insurance|social number|sin|seguridad social)\b|社保|社会保障|사회보장""")
    private val taxCtx = rx("""(?i)\b(?:tax|taxnum|tax number|tax identification|tin|vat|npwp)\b|税号|税|세금""")
    private val govCtx = rx("""(?i)\b(?:national id|identity card|id card|government id|nric|fin|dni|nie|cpf|cnpj|passport)\b|身份证|주민등록""")
    private val natIdCtx = rx("""(?iU)\b(id|ident\w*|national|personal (?:id|number|code)|pesel|bsn|burgerservice\w*|egn|ЕГН|cnp|oib|amka|ΑΜΚΑ|isikukood|henkilötunnus|hetu|codice fiscale|rodné|personnummer|personas kods|asmens kodas|emšo|emso|matricule|rijksregister\w*|steuer\w*|dni|nie|nif|nir|insee|sécu\w*|sécurité sociale|rodné|rodné číslo|adóazonosító|adószám|cpr|nip|partita iva|p\.?\s?iva|\biva\b|vat|svnr|sozialversicherung\w*|pps\w*|tax|fiscal\w*|social|seguridad)\b""")
    private val vatCtx = rx("""(?iU)\b(vat|ust[- ]?id\w*|umsatzsteuer|tva|iva|partita iva|btw|moms|alv|dph|di[cč]|pvn|pvm|dds|nip|nif|cif|[aá]fa|arvonlis\w*|fiscal\w*|tax)\b|ΑΦΜ|ФДС""")
    private val imeiCtx = rx("""(?i)\bimei\b""")
    private val sePnCtx = rx("""(?i)\b(?:personnummer|person\s*number|födelsenummer|personnr)\b""")
    private val passportCtx = rx("""(?i)\b(?:passport|passeport|reisepass|pasaporte|passaporto|paspoort)\b""")
    private val ppsCtx = rx("""(?i)\b(?:pps|ppsn|personal\s*public\s*service)\b""")
    private val dkCprCtx = rx("""(?i)\bcpr\b""")
    private val bicBefore = rx("""(?i)(?:swift\s*[-/]?\s*bic|swift\s+code|bic(?:\s+code)?)\s*[:#=(\[]?\s*$""")
    private val creditCtx = rx("""(?i)\b(?:credit\s*card|debit\s*card|payment\s*card|bank\s*card|card\s*(?:number|no|num|info|ending|on file)|card\s*(?:charged|debited)|charged?\s*(?:my\s*|the\s*)?card|\bcard\b|visa|mastercard|master\s*card|maestro|amex|american\s*express|discover|diners|tarjeta|carte bancaire|kreditkarte|carta di credito|cartão)\b|信用卡|银行卡|カード|카드""")
    private val phoneCtx = rx("""(?i)\b(?:phone|mobile|tel(?:ephone)?|cell|call(?:\s*me)?|fax|whatsapp|sms|contact number|phone number|telefon(?:ní|nummer|szám|o|oon)?|teléfono|téléphone|telepon|mobil(?:e|ni|telefon)?|gsm|tlf|zavolejte|zadzwoń|appelez|appeler|téléphonez|chiamare|chiami|chiama|llame|llamar|llamada|ligue|ligar|bel(?:len)?|hívja|hívjon|sunați|sună|ring|ringa|nazovite|καλέστε|τηλέφωνο|телефон)\b|电话|電話|연락처|전화""")

    // ---- numeric helpers ----
    private fun dl(s: String): IntArray = s.filter { it in '0'..'9' }.map { it - '0' }.toIntArray()
    private fun digitCount(s: String) = s.count { it in '0'..'9' }
    private fun wsum(d: IntArray, w: IntArray): Int { var s = 0; val n = minOf(d.size, w.size); for (i in 0 until n) s += d[i] * w[i]; return s }
    private fun luhnLen(d: IntArray): Boolean {
        var total = 0; val parity = d.size % 2
        for (i in d.indices) { var x = d[i]; if (i % 2 == parity) { x *= 2; if (x > 9) x -= 9 }; total += x }
        return total % 10 == 0
    }
    private fun toInt(d: IntArray, from: Int, to: Int): Long { var v = 0L; for (i in from until to) v = v * 10 + d[i]; return v }

    // ---- checksums ----
    private fun luhnOk(s: String): Boolean { val d = dl(s); return d.size in 13..19 && luhnLen(d) }
    private fun imeiOk(s: String): Boolean { val d = dl(s); return d.size == 15 && luhnLen(d) }
    private fun validSePn(s: String): Boolean { var d = dl(s); if (d.size == 12) d = d.copyOfRange(2, 12); return d.size == 10 && luhnLen(d) }

    private val ibanLen = mapOf(
        "AD" to 24,"AE" to 23,"AL" to 28,"AT" to 20,"AZ" to 28,"BA" to 20,"BE" to 16,"BG" to 22,"BH" to 22,"BR" to 29,"BY" to 28,"CH" to 21,"CR" to 22,"CY" to 28,"CZ" to 24,"DE" to 22,"DK" to 18,"DO" to 28,"EE" to 20,"EG" to 29,"ES" to 24,"FI" to 18,"FO" to 18,"FR" to 27,"GB" to 22,"GE" to 22,"GI" to 23,"GL" to 18,"GR" to 27,"GT" to 28,"HR" to 21,"HU" to 28,"IE" to 22,"IL" to 23,"IS" to 26,"IT" to 27,"JO" to 30,"KW" to 30,"KZ" to 20,"LB" to 28,"LC" to 32,"LI" to 21,"LT" to 20,"LU" to 20,"LV" to 21,"MC" to 27,"MD" to 24,"ME" to 22,"MK" to 19,"MR" to 27,"MT" to 31,"MU" to 30,"NL" to 18,"NO" to 15,"PK" to 24,"PL" to 28,"PS" to 29,"PT" to 25,"QA" to 29,"RO" to 24,"RS" to 22,"SA" to 24,"SC" to 31,"SE" to 24,"SI" to 19,"SK" to 24,"SM" to 27,"TN" to 24,"TR" to 26,"UA" to 29,"VG" to 24,"XK" to 20,
    )
    private fun ibanOk(value: String): Boolean {
        val s = value.replace(" ", "").uppercase()
        if (!Regex("""^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$""").matches(s)) return false
        if (s.length != (ibanLen[s.substring(0, 2)] ?: -1)) return false
        val r = s.substring(4) + s.substring(0, 4)
        var rem = 0
        for (c in r) { val part = if (c in 'A'..'Z') (c - 'A' + 10).toString() else c.toString(); for (ch in part) rem = (rem * 10 + (ch - '0')) % 97 }
        return rem == 1
    }
    private fun abaRoutingOk(v: String): Boolean {
        if (!Regex("""^\d{9}$""").matches(v)) return false
        val d = dl(v)
        return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 == 0
    }
    private fun validUsSsn(v: String): Boolean {
        val m = Regex("""^(\d{3})[- ](\d{2})[- ](\d{4})$""").find(v) ?: return false
        val (a, g, ser) = m.destructured
        val ai = a.toInt()
        if (a == "000" || a == "666" || ai in 900..999) return false
        return g != "00" && ser != "0000"
    }
    private fun bicOk(v: String): Boolean {
        if (v != v.uppercase() || !Regex("""^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$""").matches(v)) return false
        val c = v.substring(4, 6); return c != "AA" && c != "ZZ"
    }
    private fun esDniOk(v: String): Boolean {
        val s = v.uppercase()
        if (!Regex("""^(?:\d{8}|[XYZ]\d{7})[A-Z]$""").matches(s)) return false
        val num = when (s[0]) { 'X' -> ("0" + s.substring(1, 8)).toInt(); 'Y' -> ("1" + s.substring(1, 8)).toInt(); 'Z' -> ("2" + s.substring(1, 8)).toInt(); else -> s.substring(0, 8).toInt() }
        return s.last() == "TRWAGMYFPDXBNJZSQVHLCKE"[num % 23]
    }

    // national IDs (by digit count)
    private fun plPeselOk(v: String): Boolean { val d = dl(v); if (d.size != 11) return false; if ((10 - wsum(d.copyOf(10), intArrayOf(1,3,7,9,1,3,7,9,1,3)) % 10) % 10 != d[10]) return false; val mm = (d[2]*10+d[3]) % 20; return mm in 1..12 && (d[4]*10+d[5]) in 1..31 }
    private fun nlBsnOk(v: String): Boolean { val d = dl(v); return d.size == 9 && d.any { it != 0 } && (wsum(d.copyOf(8), intArrayOf(9,8,7,6,5,4,3,2)) - d[8]) % 11 == 0 }
    private fun bgEgnOk(v: String): Boolean { val d = dl(v); if (d.size != 10) return false; var c = wsum(d.copyOf(9), intArrayOf(2,4,8,5,10,9,7,3,6)) % 11; if (c == 10) c = 0; if (c != d[9]) return false; var mm = d[2]*10+d[3]; mm = if (mm in 21..32) mm-20 else if (mm in 41..52) mm-40 else mm; return mm in 1..12 && (d[4]*10+d[5]) in 1..31 }
    private fun roCnpOk(v: String): Boolean { val d = dl(v); if (d.size != 13) return false; var c = wsum(d.copyOf(12), intArrayOf(2,7,9,1,4,6,3,5,8,2,7,9)) % 11; if (c == 10) c = 1; return c == d[12] && d[0] in 1..9 && (d[3]*10+d[4]) in 1..12 && (d[5]*10+d[6]) in 1..31 }
    private fun hrOibOk(v: String): Boolean { val d = dl(v); if (d.size != 11) return false; var r = 10; for (i in 0 until 10) { r = (r + d[i]) % 10; if (r == 0) r = 10; r = (r * 2) % 11 }; return (11 - r) % 10 == d[10] }
    private fun eeIsikukoodOk(v: String): Boolean { val d = dl(v); if (d.size != 11) return false; var c = wsum(d.copyOf(10), intArrayOf(1,2,3,4,5,6,7,8,9,1)) % 11; if (c == 10) { c = wsum(d.copyOf(10), intArrayOf(3,4,5,6,7,8,9,1,2,3)) % 11; if (c == 10) c = 0 }; return c == d[10] }
    private fun grAmkaOk(v: String): Boolean { val d = dl(v); if (d.size != 11 || (d[2]*10+d[3]) !in 1..12) return false; return luhnLen(d) }
    private fun ptNifOk(v: String): Boolean { val d = dl(v); if (d.size != 9 || d[0] !in intArrayOf(1,2,3,5,6,8,9)) return false; var c = 11 - wsum(d.copyOf(8), intArrayOf(9,8,7,6,5,4,3,2)) % 11; if (c >= 10) c = 0; return c == d[8] }
    private fun frNirOk(v: String): Boolean { val d = dl(v); if (d.size != 15 || (d[0] != 1 && d[0] != 2)) return false; val k = (97 - (toInt(d, 0, 13) % 97)).toInt(); return d[13]*10+d[14] == (if (k == 0) 97 else k) }
    private fun beRrnOk(v: String): Boolean { val d = dl(v); if (d.size != 11) return false; val base = toInt(d, 0, 9); val chk = d[9]*10+d[10]; return ((97 - base % 97) % 97).toInt() == chk || ((97 - (2_000_000_000L + base) % 97) % 97).toInt() == chk }
    private fun czRcOk(v: String): Boolean { val d = dl(v); if (d.size != 10) return false; val mm = d[2]*10+d[3]; if (intArrayOf(0,20,50,70).none { (mm - it) in 1..12 }) return false; return toInt(d, 0, 10) % 11 == 0L }
    private fun siEmsoOk(v: String): Boolean { val d = dl(v); if (d.size != 13 || (d[2]*10+d[3]) !in 1..12) return false; val m = wsum(d.copyOf(12), intArrayOf(7,6,5,4,3,2,7,6,5,4,3,2)) % 11; val chk = if (m == 0) 0 else 11 - m; return chk != 10 && chk == d[12] }
    private fun huAdoazOk(v: String): Boolean { val d = dl(v); if (d.size != 10 || d[0] != 8) return false; var c = 0; for (i in 0 until 9) c += d[i] * (i + 1); c %= 11; return c != 10 && c == d[9] }
    private fun lvPkOk(v: String): Boolean { val d = dl(v); if (d.size != 11 || d[0] == 3 || (d[2]*10+d[3]) !in 1..12) return false; return ((1 - wsum(d.copyOf(10), intArrayOf(1,6,3,7,9,10,5,8,4,2))) % 11 + 11) % 11 % 10 == d[10] }
    private fun plNipOk(v: String): Boolean { val d = dl(v); if (d.size != 10) return false; val c = wsum(d.copyOf(9), intArrayOf(6,5,7,2,3,4,5,6,7)) % 11; return c != 10 && c == d[9] }
    private fun itPivaOk(v: String): Boolean { val d = dl(v); if (d.size != 11) return false; var x = 0; var y = 0; var i = 0; while (i < 10) { x += d[i]; i += 2 }; i = 1; while (i < 10) { val t = d[i]*2; y += if (t > 9) t-9 else t; i += 2 }; return (10 - (x+y) % 10) % 10 == d[10] }
    private fun atSvnrOk(v: String): Boolean { val d = dl(v); if (d.size != 10) return false; val w = intArrayOf(3,7,9,0,5,8,4,2,1,6); var c = 0; for (i in 0 until 10) if (i != 3) c += d[i]*w[i]; c %= 11; return c != 10 && c == d[3] }
    private fun iePpsOk(v: String): Boolean { val m = Regex("""^(\d{7})([A-W])([A-W]?)$""").find(v.uppercase()) ?: return false; val d = m.groupValues[1]; var s = 0; for (i in 0 until 7) s += (d[i]-'0')*(8-i); val c2 = m.groupValues[3]; if (c2.isNotEmpty()) s += (c2[0].code - 64)*9; return "WABCDEFGHIJKLMNOPQRSTUV"[s % 23] == m.groupValues[2][0] }
    private val cfOdd = mapOf('0' to 1,'1' to 0,'2' to 5,'3' to 7,'4' to 9,'5' to 13,'6' to 15,'7' to 17,'8' to 19,'9' to 21,'A' to 1,'B' to 0,'C' to 5,'D' to 7,'E' to 9,'F' to 13,'G' to 15,'H' to 17,'I' to 19,'J' to 21,'K' to 2,'L' to 4,'M' to 18,'N' to 20,'O' to 11,'P' to 3,'Q' to 6,'R' to 8,'S' to 12,'T' to 14,'U' to 16,'V' to 10,'W' to 22,'X' to 25,'Y' to 24,'Z' to 23)
    private fun itCfOk(v: String): Boolean { val s = v.uppercase(); if (!Regex("""^[A-Z0-9]{16}$""").matches(s)) return false; var tot = 0; for (i in 0 until 15) { tot += if (i % 2 == 0) cfOdd.getValue(s[i]) else (if (s[i] in '0'..'9') s[i]-'0' else s[i].code - 65) }; return (65 + tot % 26).toChar() == s[15] }
    private fun fiHetuOk(v: String): Boolean { val s = v.replace(" ", "").uppercase(); val m = Regex("""^(\d{6})[-+A-F](\d{3})([0-9A-Y])$""").find(s) ?: return false; val n = (m.groupValues[1] + m.groupValues[2]).toInt(); return "0123456789ABCDEFHJKLMNPRSTUVWXY"[n % 31] == m.groupValues[3][0] }

    private val natValidators: Map<Int, List<(String) -> Boolean>> = mapOf(
        9 to listOf(::nlBsnOk, ::ptNifOk),
        10 to listOf(::bgEgnOk, ::czRcOk, ::huAdoazOk, ::plNipOk, ::atSvnrOk),
        11 to listOf(::plPeselOk, ::hrOibOk, ::grAmkaOk, ::eeIsikukoodOk, ::lvPkOk, ::beRrnOk, ::itPivaOk),
        13 to listOf(::roCnpOk, ::siEmsoOk),
        15 to listOf(::frNirOk),
    )

    // VAT (per-country checksum)
    private val vatFmtOnly = setOf("ES", "LV", "NL")
    private fun m(p: String, n: String) = Regex("^$p$").matches(n)
    private val vat: Map<String, (String) -> Boolean> = buildMap {
        put("AT") { n -> if (!m("""U\d{8}""", n)) false else { val d = dl(n); var s = 4; for (i in 0 until 7) { var x = d[i] * (if (i % 2 == 1) 2 else 1); if (x > 9) x -= 9; s += x }; (10 - s % 10) % 10 == d[7] } }
        put("BE") { n -> m("""0\d{9}""", n) && (97 - n.substring(0, 8).toInt() % 97) == n.substring(8).toInt() }
        put("BG") { n -> if (m("""\d{9}""", n)) { val d = dl(n); var s = 0; for (i in 0 until 8) s += d[i]*(i+1); s %= 11; if (s == 10) { s = 0; for (i in 0 until 8) s += d[i]*(i+3); s %= 11; if (s == 10) s = 0 }; s == d[8] } else m("""\d{10}""", n) && bgEgnOk(n) }
        put("CY") { n -> if (!m("""\d{8}[A-Z]""", n)) false else { val tr = intArrayOf(1,0,5,7,9,13,15,17,19,21); val d = dl(n); var s = 0; for (i in 0 until 8) s += if (i % 2 == 0) tr[d[i]] else d[i]; (65 + s % 26).toChar() == n[8] } }
        put("CZ") { n -> if (m("""\d{8}""", n)) { val d = dl(n); var s = 0; for (i in 0 until 7) s += d[i]*(8-i); s %= 11; (11 - s) % 10 == d[7] } else m("""\d{10}""", n) && czRcOk(n) }
        put("DE") { n -> if (!m("""\d{9}""", n)) false else { val d = dl(n); var p = 10; for (i in 0 until 8) { var s = (d[i] + p) % 10; if (s == 0) s = 10; p = (s*2) % 11 }; (11 - p) % 10 == d[8] } }
        put("DK") { n -> m("""\d{8}""", n) && wsum(dl(n), intArrayOf(2,7,6,5,4,3,2,1)) % 11 == 0 }
        put("EE") { n -> m("""\d{9}""", n) && (10 - wsum(dl(n).copyOf(8), intArrayOf(3,7,1,3,7,1,3,7)) % 10) % 10 == dl(n)[8] }
        put("EL") { n -> if (!m("""\d{9}""", n)) false else { val d = dl(n); var s = 0; for (i in 0 until 8) s += d[i] * (1 shl (8-i)); s %= 11; (if (s < 10) s else 0) == d[8] } }
        put("ES") { n -> m("""[A-Z0-9]\d{7}[A-Z0-9]""", n) }
        put("FI") { n -> if (!m("""\d{8}""", n)) false else { val d = dl(n); val s = wsum(d.copyOf(7), intArrayOf(7,9,10,5,8,4,2)) % 11; s != 1 && (if (s == 0) 0 else 11-s) == d[7] } }
        put("FR") { n -> if (!m("""\d{11}""", n)) false else { val siren = n.substring(2); val d = dl(siren); var ls = 0; for (i in d.indices) { var x = d[d.size-1-i] * (if (i % 2 == 1) 2 else 1); if (x > 9) x -= 9; ls += x }; ls % 10 == 0 && n.substring(0, 2).toInt() == (12 + 3 * (siren.toLong() % 97)).toInt() % 97 } }
        put("HR") { n -> hrOibOk(n) }
        put("HU") { n -> m("""\d{8}""", n) && (10 - wsum(dl(n).copyOf(7), intArrayOf(9,7,3,1,9,7,3)) % 10) % 10 == dl(n)[7] }
        put("IE") { n -> val mm = Regex("""^(\d{7})([A-W])([A-W]?)$""").find(n) ?: return@put false; val d = mm.groupValues[1]; var s = 0; for (i in 0 until 7) s += (d[i]-'0')*(8-i); val c2 = mm.groupValues[3]; if (c2.isNotEmpty()) s += (c2[0].code-64)*9; "WABCDEFGHIJKLMNOPQRSTUV"[s % 23] == mm.groupValues[2][0] }
        put("IT") { n -> itPivaOk(n) }
        put("LT") { n -> if (!m("""\d{9}|\d{12}""", n)) false else { val d = dl(n); val k = d.size; var s = 0; for (i in 0 until k-1) s += d[i] * ((i % 9)+1); s %= 11; if (s == 10) { s = 0; for (i in 0 until k-1) s += d[i] * ((i % 9)+3); s %= 11; if (s == 10) s = 0 }; s == d[k-1] } }
        put("LU") { n -> m("""\d{8}""", n) && n.substring(0, 6).toInt() % 89 == n.substring(6).toInt() }
        put("LV") { n -> m("""\d{11}""", n) }
        put("MT") { n -> m("""\d{8}""", n) && (37 - wsum(dl(n).copyOf(6), intArrayOf(3,4,6,7,8,9)) % 37) % 37 == n.substring(6).toInt() }
        put("NL") { n -> m("""\d{9}B\d{2}""", n) }
        put("PL") { n -> plNipOk(n) }
        put("PT") { n -> ptNifOk(n) }
        put("RO") { n -> if (!m("""\d{2,10}""", n)) false else { val b = n.dropLast(1); val full = intArrayOf(7,5,3,2,1,7,5,3,2); val w = full.copyOfRange(full.size - b.length, full.size); var s = 0; for (i in b.indices) s += (b[i]-'0')*w[i]; s = (s*10) % 11; (if (s == 10) 0 else s) == (n.last()-'0') } }
        put("SE") { n -> if (!m("""\d{10}01""", n)) false else { val d = dl(n).copyOf(10); var ls = 0; for (i in 0 until 10) { var x = d[i] * (if (i % 2 == 0) 2 else 1); if (x > 9) x -= 9; ls += x }; ls % 10 == 0 } }
        put("SI") { n -> if (!m("""\d{8}""", n)) false else { val s = wsum(dl(n).copyOf(7), intArrayOf(8,7,6,5,4,3,2)) % 11; val c = 11 - s; c != 10 && (if (c == 11) 0 else c) == dl(n)[7] } }
        put("SK") { n -> m("""\d{10}""", n) && n.toLong() % 11 == 0L }
        put("GR") { n -> getValue("EL")(n) }
    }

    private fun hasContext(re: Regex, text: String, start: Int, end: Int, window: Int = 48): Boolean =
        re.containsMatchIn(text.substring(maxOf(0, start - window), minOf(text.length, end + window)))
    private fun before(re: Regex, text: String, start: Int, window: Int = 64): Boolean =
        re.containsMatchIn(text.substring(maxOf(0, start - window), start))
    private fun isIp(v: String): Boolean {
        if (Regex("""^(\d{1,3}\.){3}\d{1,3}$""").matches(v)) return v.split(".").all { (it.toIntOrNull() ?: 999) <= 255 }
        if (Regex("""^[0-9a-f:]+$""", RegexOption.IGNORE_CASE).matches(v) && v.contains(":") && v != ":" && v != "::") return v.split("::").size <= 2
        return false
    }
    private fun trimWord(text: String, v0: String, end0: Int): Pair<String, Int> {
        var chars = v0; var end = end0
        while (chars.length >= 2 && chars[chars.length-1].isLetter() && chars[chars.length-2] == ' ' && end < text.length && text[end] in 'a'..'z') { chars = chars.dropLast(2); end -= 2 }
        return chars to end
    }

    fun detect(text: String, enabled: Set<String>? = null): List<Span> {
        val en = enabled ?: owned
        val spans = ArrayList<Span>()
        fun add(s: Int, e: Int, label: String, score: Double = 1.0) { if (s < e) spans.add(Span(s, e, label, score)) }
        fun gr(m: MatchResult, g: Int): IntRange? = m.groups[g]?.range

        for (mt in emailRe.findAll(text)) { val g = gr(mt, 1)!!; add(g.first, g.last + 1, "EMAIL") }
        for (mt in urlRe.findAll(text)) { val g = gr(mt, 1)!!; if (g.first > 0 && text[g.first - 1] == '@') continue; add(g.first, g.last + 1, "URL") }
        for (mt in ipv4Re.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (isIp(mt.value) && hasContext(ipCtx, text, a, b, 40)) add(a, b, "IP_ADDRESS") }
        for (mt in ipv6Re.findAll(text)) { val v = mt.value; if (v == ":" || v == "::") continue; val a = mt.range.first; val b = mt.range.last + 1; if (isIp(v) && hasContext(ipCtx, text, a, b, 40)) add(a, b, "IP_ADDRESS") }
        for (mt in macRe.findAll(text)) add(mt.range.first, mt.range.last + 1, "IP_ADDRESS")
        for (mt in ccRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; val v = mt.value; val dg = v.filter { it in '0'..'9' }; if (dg.toSet().size <= 1) continue; if (luhnOk(v) && creditCtx.containsMatchIn(text.substring(maxOf(0, a - 56), a))) { var end = b; while (end > a && text[end - 1] in " -.") end--; add(a, end, "CREDIT_CARD") } }
        for (mt in ibanRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (ibanOk(mt.value)) add(a, b, "BANK_ACCOUNT") }
        for (mt in bicRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (bicOk(mt.value) && before(bicBefore, text, a, 64)) add(a, b, "BANK_ACCOUNT") }
        for (mt in esDniRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (esDniOk(mt.value) && hasContext(govCtx, text, a, b, 56)) add(a, b, "GOVERNMENT_ID") }
        for (mt in natIdRe.findAll(text)) { val d = mt.value; val vals = natValidators[digitCount(d)]; val a = mt.range.first; val b = mt.range.last + 1; if (vals != null && vals.any { it(d) } && hasContext(natIdCtx, text, a, b, 64)) add(a, b, "GOVERNMENT_ID", 0.92) }
        for (mt in itCfRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (itCfOk(mt.value)) add(a, b, "GOVERNMENT_ID", 0.95) }
        for (mt in fiHetuRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (fiHetuOk(mt.value)) add(a, b, "GOVERNMENT_ID", 0.95) }
        for (mt in dkCprRe.findAll(text)) { val d = dl(mt.value); val a = mt.range.first; val b = mt.range.last + 1; if ((d[0]*10+d[1]) in 1..31 && (d[2]*10+d[3]) in 1..12 && before(dkCprCtx, text, a, 40)) add(a, b, "GOVERNMENT_ID", 0.85) }
        for (mt in vatRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; val cc = mt.groupValues[1]; val num = mt.groupValues[2].replace(" ", "").uppercase(); val fn = vat[cc]; if (fn != null && fn(num) && (cc !in vatFmtOnly || hasContext(vatCtx, text, a, b, 40))) add(a, b, "TAX_ID", 0.95) }
        for (mt in imeiRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (imeiOk(mt.value) && hasContext(imeiCtx, text, a, b, 32)) add(a, b, "IMEI", 0.9) }
        for (mt in ssnRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (validUsSsn(mt.value) || hasContext(ssnCtx, text, a, b)) add(a, b, "SSN") }
        for (mt in sePnRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (validSePn(mt.value) || before(sePnCtx, text, a, 40)) add(a, b, "GOVERNMENT_ID") }
        for (mt in passportValRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (mt.value.any { it in '0'..'9' } && before(passportCtx, text, a, 32)) add(a, b, "PASSPORT") }
        for (mt in dlKwRe.findAll(text)) { val g2 = mt.groups[2] ?: continue; val (v, end) = trimWord(text, g2.value, g2.range.last + 1); if (v.count { it.isLetterOrDigit() } >= 5) add(g2.range.first, end, "DRIVERS_LICENSE", 0.9) }
        for (mt in plDlRe.findAll(text)) add(mt.range.first, mt.range.last + 1, "DRIVERS_LICENSE", 0.9)
        for (mt in docIdKwRe.findAll(text)) { val g2 = mt.groups[2] ?: continue; val (v, end) = trimWord(text, g2.value, g2.range.last + 1); if (v.any { it in '0'..'9' } && v.count { it.isLetterOrDigit() } >= 6) { val lab = if (passportKwRe.containsMatchIn(mt.groupValues[1])) "PASSPORT" else "GOVERNMENT_ID"; add(g2.range.first, end, lab, 0.9) } }
        for (mt in ppsRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (iePpsOk(mt.value) || hasContext(ppsCtx, text, a, b, 32)) add(a, b, "GOVERNMENT_ID") }
        for (mt in contextDigitRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; val dgn = digitCount(mt.value); val bef = text.substring(maxOf(0, a - 56), a); if (dgn in 7..12 && ssnCtx.containsMatchIn(bef) && !taxCtx.containsMatchIn(bef)) add(a, b, "SSN", 0.9) }
        for (mt in routingRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; if (abaRoutingOk(mt.value) && hasContext(routingCtx, text, a, b)) add(a, b, "ROUTING_NUMBER") }
        for (mt in intlPhoneRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; val nn = digitCount(mt.value); if (nn in 8..15) add(a, b, "PHONE", 0.92) }
        for (mt in genericPhoneRe.findAll(text)) { val a = mt.range.first; val b = mt.range.last + 1; val raw = mt.value; val dg = digitCount(raw); val bef = text.substring(maxOf(0, a - 56), a); val grouped = raw.any { it == ' ' || it == '.' || it == '-' }; if (phoneCtx.containsMatchIn(bef) && ((dg in 9..15) || (dg in 7..8 && grouped))) add(a, b, "PHONE", 0.88) }

        return merge(spans).filter { it.label in en }
    }

    private fun merge(spans: List<Span>): List<Span> {
        val ordered = spans.sortedWith(compareBy({ it.start }, { -(it.end - it.start) }, { it.label }))
        val out = ArrayList<Span>()
        for (s in ordered) {
            if (out.isEmpty() || s.start >= out.last().end) out.add(s)
            else { val p = out.last(); val sl = s.end - s.start; val pl = p.end - p.start; if (sl > pl || (sl == pl && s.score > p.score)) out[out.size - 1] = s }
        }
        return out
    }
}
