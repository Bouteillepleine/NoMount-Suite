//! Curated hide-list presets

/// Preset name accepted on the command line and by the WebUI
pub const DETECTORS: &str = "detectors";

/// Every preset the CLI knows, as `(name, description)`
pub const ALL: &[(&str, &str)] = &[(DETECTORS, "known root / environment detectors")];

/// Package-name globs
pub const DETECTOR_PATTERNS: &[&str] = &[
    "me.garfieldhan.*",
    "*chunqiu*",
    "*chuqniu*",
    "*.duckdetector",
    "*.keyattestation",
];

/// Detectors that ship under a stable package name
pub const DETECTOR_PACKAGES: &[&str] = &[
    "com.reveny.nativecheck",
    "icu.nullptr.nativetest",
    "io.github.rabehx.securify",
    "com.zhenxi.hunter",
    "io.github.vvb2060.mahoshojo",
    "io.github.huskydg.memorydetector",
    "org.akanework.checker",
    "icu.nullptr.applistdetector",
    "com.byxiaorun.detector",
    "com.kimchangyoun.rootbeerFresh.sample",
    "com.androidfung.drminfo",
    "com.kikyps.crackme",
    "org.matrix.demo",
    "com.rem01gaming.disclosure",
    "luna.safe.luna",
    "com.AndroLua",
    "com.detect.mt",
    "io.liankong.riskdetector",
    "com.suisho.rc",
    "com.ahmed.security_tester",
    "id.my.pjm.qbcd_okr_dvii",
    "wu.Zygisk.Detector",
    "com.atominvention.rootchecker",
    "com.joeykrim.rootcheck",
    "com.longz.detector",
    "com.anycheck.app",
    "by.sheerboy.femboydetector",
    "com.lingqing.detector",
    "com.android.nativetest",
    "com.youhu.laifu",
    "wu.Rookie.Detector",
    "com.fkjc.zcro",
    "wu.keyChain.test",
    "at.persie0.root_detection_app",
    "at.austriao.fake_gps_detector_app",
    "io.ngankbakaa.lineage.detector",
    "com.dexprotector.detector.envchecks",
    "krypton.tbsafetychecker",
    "gr.nikolasspyr.integritycheck",
    "com.henrikherzig.playintegritychecker",
    "com.thend.integritychecker",
    "com.flinkapps.safteynet",
    "com.bryancandi.knoxcheck",
];

/// Look a preset up by name
pub fn get(name: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    match name.trim().to_ascii_lowercase().as_str() {
        DETECTORS => Some((DETECTOR_PATTERNS, DETECTOR_PACKAGES)),
        _ => None,
    }
}

/// Every entry of a preset, globs first so a `uid list` reads patterns-then-names
pub fn entries(name: &str) -> Option<Vec<String>> {
    let (pats, pkgs) = get(name)?;
    Some(pats.iter().chain(pkgs.iter()).map(|s| s.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::Pattern;

    #[test]
    fn every_preset_pattern_is_well_formed_and_not_too_broad() {
        for p in DETECTOR_PATTERNS {
            let parsed = Pattern::parse(p).unwrap_or_else(|| panic!("{p} is not a glob"));
            parsed.unwrap_or_else(|e| panic!("{p} rejected: {e}"));
        }
    }

    #[test]
    fn preset_packages_are_plain_names_not_globs() {
        for p in DETECTOR_PACKAGES {
            assert!(!p.contains('*'), "{p} belongs in DETECTOR_PATTERNS");
            assert!(p.contains('.'), "{p} is not a package name");
        }
    }

    #[test]
    fn detector_globs_catch_the_ones_we_tore_down() {
        let hits = |pkg: &str| {
            DETECTOR_PATTERNS
                .iter()
                .filter_map(|p| Pattern::parse(p).and_then(|r| r.ok()))
                .any(|p| p.matches(pkg))
        };
        assert!(hits("me.garfieldhan.holmes"));
        assert!(hits("com.example.duckdetector"));
        assert!(hits("io.chunqiu.detector"));
        assert!(!hits("com.google.android.gms"));
        assert!(!hits("com.resukisu.resukisu"));
    }

    #[test]
    fn unknown_preset_is_none() {
        assert!(get("nope").is_none());
        assert!(entries(DETECTORS).is_some_and(|e| e.len() > 40));
    }
}
