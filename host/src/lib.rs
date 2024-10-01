// host/src/lib.rs
#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::time::Instant;
    use chrono::Utc;
    use fs2::FileExt;
    use function_name::named;
    use hex_literal::hex;
    use risc0_zkvm::{default_prover, ExecutorEnv, ProveInfo, Receipt};
    use methods::GUEST_CODE_FOR_ZK_PROOF_ELF;
    use cometbls_groth16_verifier::VerifyZkpRequest;
    use std::io::Write;

    #[test]
    #[named]
    fn test_valid_proof() {
        // Set up the input as in your first test case
        let input = VerifyZkpRequest {
            chain_id: "union-devnet-1337".into(),
            trusted_validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            height: 3405691582,
            seconds: 1710783278,
            nanos: 499600406,
            validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            next_validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            app_hash: hex!("3A34FC963EEFAAE9B7C0D3DFF89180D91F3E31073E654F732340CEEDD77DD25B").into(),
            zkp: hex!("294A48A750D5C2CF926516752FF484EEBE55FF26CF8A8A7536D98794CF062DB6214D0C9E5C6B164111927A1630889619DBBB40149D8E2D32898E7ACB765542CD0EB8A8E04CCC254C3BFDC2FCE627D59C3C05E2AC76E03977855DD889C1C9BA432FF7FF4DEFCB5286555D36D22DD073A859140508AF9B977F38EB9A604E99A5F6109D43A4AFA0AB161DA2B261DED80FBC0C36E57DE2001338941C834E3262CF751BC1BFC6EC27BB8E106BAAB976285BAC1D4AC38D1B759C8A2852D65CE239974F1275CC6765B3D174FD1122EFDE86137D19F07483FEF5244B1D74B2D9DC598AC32A5CA10E8837FBC89703F4D0D46912CF4AF82341C30C2A1F3941849CC011A56E18AD2162EEB71289B8821CC01875BC1E35E5FC1EBD9114C0B2C0F0D9A96C394001468C70A1716CA98EBE82B1E614D4D9B07292EBAD5B60E0C76FD1D58B485E7D1FB1E07F51A0C68E4CA59A399FCF0634D9585BE478E37480423681B984E96C0A1698D8FCB1DF51CAE023B045E114EED9CB233A5742D9E60E1097206EB20A5058").into(), // Truncated for brevity
        };

        let receipt = create_receipt(function_name!(), &input);

        let result: bool = receipt.journal.decode().unwrap();

        assert!(result, "Proof should be valid");
    }

    #[test]
    #[named]
    fn test_invalid_proof() {
        let input = VerifyZkpRequest {
            chain_id: "union-devnet-1337".into(),
            trusted_validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            height: 34056915832, // Tampered height
            seconds: 1710783278,
            nanos: 499600406,
            validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            next_validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            app_hash: hex!("3A34FC963EEFAAE9B7C0D3DFF89180D91F3E31073E654F732340CEEDD77DD25B").into(),
            zkp: hex!("294A48A750D5C2CF926516752FF484EEBE55FF26CF8A8A7536D98794CF062DB6214D0C9E5C6B164111927A1630889619DBBB40149D8E2D32898E7ACB765542CD0EB8A8E04CCC254C3BFDC2FCE627D59C3C05E2AC76E03977855DD889C1C9BA432FF7FF4DEFCB5286555D36D22DD073A859140508AF9B977F38EB9A604E99A5F6109D43A4AFA0AB161DA2B261DED80FBC0C36E57DE2001338941C834E3262CF751BC1BFC6EC27BB8E106BAAB976285BAC1D4AC38D1B759C8A2852D65CE239974F1275CC6765B3D174FD1122EFDE86137D19F07483FEF5244B1D74B2D9DC598AC32A5CA10E8837FBC89703F4D0D46912CF4AF82341C30C2A1F3941849CC011A56E18AD2162EEB71289B8821CC01875BC1E35E5FC1EBD9114C0B2C0F0D9A96C394001468C70A1716CA98EBE82B1E614D4D9B07292EBAD5B60E0C76FD1D58B485E7D1FB1E07F51A0C68E4CA59A399FCF0634D9585BE478E37480423681B984E96C0A1698D8FCB1DF51CAE023B045E114EED9CB233A5742D9E60E1097206EB20A5058").into(), // Same ZKP data
        };

        let receipt = create_receipt(function_name!(), &input);

        let result: bool = receipt.journal.decode().unwrap();

        assert!(!result, "Proof should be invalid due to tampered height");
    }
    
    #[test]
    #[named]
    fn test_valid_block_969001() {
        let input = VerifyZkpRequest {
            chain_id: "union-testnet-8".into(),
            trusted_validators_hash: hex!("1deda64b1cc1319718f168b5aa8ed904b7d5b0ab932acdf6deae0ad9bd565a53").into(),
            height: 969001,
            seconds: 1718716856,
            nanos: 784169335,
            validators_hash: hex!("1deda64b1cc1319718f168b5aa8ed904b7d5b0ab932acdf6deae0ad9bd565a53").into(),
            next_validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            app_hash: hex!("1818da4a8b1c430557a3018adc2bf9a06e56c3b530e5cce7709232e0f03bd9ab").into(),
            zkp: hex!("086541c22b53d509d8369492d32683188f0b379950ea3c5da84aca2b331d911c163bc6e30c7610b6903832184d284399d140b316134202cfa53b695ed17db64e271a8ab10b015cc4562730180cc7af7d7509b64de00b5864ccef3ab6b5c187da1511c4af3392d5e4465cebeb3c92cad546ab6b5b7de08923ae756d4a49d972920ed4f1b33bde26016e753fe00e9ee8b37873e4df4696cce84baa34e444d6f9dc0021b25644dc22fd9414197dd9e094180eac33a5e6fc6d2e04e12df5baaae92815173080dedcafeb2789245e75f1c38ddaa4611273fa5eed1cb77f75aabace770186385a3a373190a9091147de95b3f11050152bc4376573ed454cfd703f1e7106edb33921b12717708fe03861534c812a5ea6c7e0ec428c02292f1e7dafb45901e8b29e0b18ba7cbfad2a7aef7db558f3eb49a943a379a03b1b976df912a0c329b66224da89f94e29c49b3c5070b86b23d9d23424246235088ea858a21340cc2d1120ac3dc25febd188abf16774ea49564f34bc769b6abd9295128c391dad18").into(), // First 30 characters
        };

        let receipt = create_receipt(function_name!(), &input);

        let result: bool = receipt.journal.decode().unwrap();

        assert!(result, "Proof should be valid for block 969001");
    }



    #[test]
    #[named]
    fn test_invalid_block_969002() {
        let input = VerifyZkpRequest {
            chain_id: "union-testnet-8".into(),
            trusted_validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            height: 969002,  // This block is invalid
            seconds: 1710783278,
            nanos: 499600406,
            validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            next_validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            app_hash: hex!("333f81c038816f109413eac1dc1cb8cef8facca1e9a49f21763f5dc84a375e14").into(),
            zkp: hex!("02344d05cbb4f42548eadc621c46a3ae37f2ce23c12df83d1b490414bc20749a1fd5d4bd3b62a5b2cfae9f29686bfe1bc7a7c4bde72df168bdc1c1b0a3da1deb2a3f92896f5c37b4e3269aa84b47a67cad8b072350f794a15bac37608a5d549315e3850f18ddfa58ff9cfd5b2d133c3ac08d9f76e64611e6df4b6ba3d752e6f9054ec040028d1fd50d0f39eb60cb16326ba8876f5a47eea0c8b9c61461612bd518532a44ed88602a6e81177d08018fefadb2fedeac17ec26dae578532efb8a7905e1aca9429d9b8bfd7fb04e419c034258bc2d367e1c1a63936c67aca6767d5c1ba16ebb1dfccd919fa28d12255e6f9fcb98964682ca733bc591a25bd5a7993226daae60fea7d697b714916f9a6093f40a7a0e2a2a40b41b8741a98d5337b91f21a20866c16d94855c50593175e6d61481d56d08569ca55f8aa9f73277b3782a179b1bb01a269ae4eeacf273379099c641503f20830d6ef399867024b4f3c191120c8f0c1091387705c314ee6c5d8d23bf200649fe7b8dc2857db55f7bc5968c").into(),
        };

        let receipt = create_receipt(function_name!(), &input);

        let result: bool = receipt.journal.decode().unwrap();

        assert!(!result, "Proof should be invalid for tampered block 969002");
    }

    #[test]
    #[named]
    fn test_invalid_block_969006() {
        let input = VerifyZkpRequest {
            chain_id: "union-testnet-8".into(),
            trusted_validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            height: 969006,  // Invalid block height
            seconds: 1710783278,
            nanos: 499600406,
            validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            next_validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            app_hash: hex!("333f81c038816f109413eac1dc1cb8cef8facca1e9a49f21763f5dc84a375e14").into(),
            zkp: hex!("13b9571349f3624ca8027ceb742ac0582a3d27847b794f567c0e35dc551a8e3e1c791e8efdd146de4319a39089755754a3a3b08a4ab1d343576ed085b5c924f825f284dad24cddb3614e663b3b407af8d3ec55edad709dace9266996aa91466126eb14026de607692bb70f8f6750c6245a9491bba466245f49ee08fbdc57ed12096bcc416908750ce28317609680ca01b5731237d600162f790d0c7085a6b721022f966ae2f087062644fcd20024ac0641ca732388cf360ce8cc61ac0480c7cc26a09e5a8c2e1b728fd0a37e5532fcc44dcd389314a80e0fb191d148740e436a1e4b916c9862c7ccf9073bfcb3b5dd09a3903f619e79a7c04f89cc42619fe35a074ad1bbd03821f2622c67a1ab95486896592703a846dda6e6e3c2b6213aa4791fc58b6834c89cbea52b43c31ca8c4a44378f38d06d2baa04672f7006651c2431ed56b4cc18b0b0082d919813a0f0433942b8691ec70c6305705faef970ceef00ca817ffdf6c5bfa0eaf33951e6695bc537f8345cc8f03d9f234d44dec3ff8b4").into(),  // First 20-30 characters
        };

        let receipt = create_receipt(function_name!(), &input);

        let result: bool = receipt.journal.decode().unwrap();

        assert!(!result, "Proof should be invalid for block 969006");
    }

    #[test]
    #[named]
    fn test_valid_block_969002() {
        let input = VerifyZkpRequest {
            chain_id: "union-testnet-8".into(),
            trusted_validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            height: 969002,
            seconds: 1718716862,
            nanos: 868708953,
            validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            next_validators_hash: hex!("01a84dca649aa2df8de2f65a84c9092bbd5296b4bc54d818f844b28573d8e0be").into(),
            app_hash: hex!("333f81c038816f109413eac1dc1cb8cef8facca1e9a49f21763f5dc84a375e14").into(),
            zkp: hex!("02344d05cbb4f42548eadc621c46a3ae37f2ce23c12df83d1b490414bc20749a1fd5d4bd3b62a5b2cfae9f29686bfe1bc7a7c4bde72df168bdc1c1b0a3da1deb2a3f92896f5c37b4e3269aa84b47a67cad8b072350f794a15bac37608a5d549315e3850f18ddfa58ff9cfd5b2d133c3ac08d9f76e64611e6df4b6ba3d752e6f9054ec040028d1fd50d0f39eb60cb16326ba8876f5a47eea0c8b9c61461612bd518532a44ed88602a6e81177d08018fefadb2fedeac17ec26dae578532efb8a7905e1aca9429d9b8bfd7fb04e419c034258bc2d367e1c1a63936c67aca6767d5c1ba16ebb1dfccd919fa28d12255e6f9fcb98964682ca733bc591a25bd5a7993226daae60fea7d697b714916f9a6093f40a7a0e2a2a40b41b8741a98d5337b91f21a20866c16d94855c50593175e6d61481d56d08569ca55f8aa9f73277b3782a179b1bb01a269ae4eeacf273379099c641503f20830d6ef399867024b4f3c191120c8f0c1091387705c314ee6c5d8d23bf200649fe7b8dc2857db55f7bc5968c").into(),  // First 20-30 characters
        };

        let receipt = create_receipt(function_name!(), &input);

        let result: bool = receipt.journal.decode().unwrap();

        assert!(result, "Proof should be valid for block 969002");
    }

    #[test]
    #[named]
    fn test_tampered_block_969001() {
        let input = VerifyZkpRequest {
            chain_id: "union-devnet-1337".into(),
            trusted_validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            height: 969001,  // Tampered height
            seconds: 1710783278,
            nanos: 499600406,
            validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            next_validators_hash: hex!("1B7EA0F1B3E574F8D50A12827CCEA43CFF858C2716AE05370CC40AE8EC521FD8").into(),
            app_hash: hex!("3A34FC963EEFAAE9B7C0D3DFF89180D91F3E31073E654F732340CEEDD77DD25B").into(),
            zkp: hex!("294A48A750D5C2CF926516752FF484EEBE55FF26CF8A8A7536D98794CF062DB6214D0C9E5C6B164111927A1630889619DBBB40149D8E2D32898E7ACB765542CD0EB8A8E04CCC254C3BFDC2FCE627D59C3C05E2AC76E03977855DD889C1C9BA432FF7FF4DEFCB5286555D36D22DD073A859140508AF9B977F38EB9A604E99A5F6109D43A4AFA0AB161DA2B261DED80FBC0C36E57DE2001338941C834E3262CF751BC1BFC6EC27BB8E106BAAB976285BAC1D4AC38D1B759C8A2852D65CE239974F1275CC6765B3D174FD1122EFDE86137D19F07483FEF5244B1D74B2D9DC598AC32A5CA10E8837FBC89703F4D0D46912CF4AF82341C30C2A1F3941849CC011A56E18AD2162EEB71289B8821CC01875BC1E35E5FC1EBD9114C0B2C0F0D9A96C394001468C70A1716CA98EBE82B1E614D4D9B07292EBAD5B60E0C76FD1D58B485E7D1FB1E07F51A0C68E4CA59A399FCF0634D9585BE478E37480423681B984E96C0A1698D8FCB1DF51CAE023B045E114EED9CB233A5742D9E60E1097206EB20A5058").into(),  // First 20-30 characters
        };

        let receipt = create_receipt(function_name!(), &input);

        let result: bool = receipt.journal.decode().unwrap();

        assert!(!result, "Proof should be invalid due to tampered height for block 969001");
    }

    #[test]
    #[named]
    fn test_invalid_verifying_key() {
        let input = VerifyZkpRequest {
            chain_id: "union-devnet-1".into(),
            trusted_validators_hash: hex!("2f4975ab7e75a677f43efebf53e0ec05460d2cf55506ad08d6b05254f96a500d").into(),
            height: 905,
            seconds: 1710783278, //2024-09-23T20:48:00.739712762Z
            nanos: 499600406,
            validators_hash: hex!("2f4975ab7e75a677f43efebf53e0ec05460d2cf55506ad08d6b05254f96a500d").into(),
            next_validators_hash: hex!("2f4975ab7e75a677f43efebf53e0ec05460d2cf55506ad08d6b05254f96a500d").into(),
            app_hash: hex!("eddaa32275fbbf44c6a21e32b59b097bed5374be715eab22f093399a9700a1e4").into(),
            zkp: hex!("1d530ee22263bc9e7008e3bd982c966b226d1018814e5b4d07597b4d35aea56b2ef63fdddb29fe06ef99cf645201a12e8b98b9ff7a7cec0819f696e17413294b0c638c4f946f4d4af4da8dd0815de2f5af8fd8612d1c98e9846846ea1ec78aac046df852b916de3fd8b3332bc3d23073e11b252b023711c18b19952507428da12e2baf74a03ca7bdc37edd0123e47f0a3a029f6da43a32dc6830e126b4ddf8712f2a0e021ac0f6414f171156f6a9019d6ea53cd30762c1e60d6a0e029778586c0cc1e2e13f7c45347a2a3ba82e43eccdc468fc8a05ba0a95fef26777872c27e42317f2c76c0a5f41e63088b8b394c5a7a3066809952f489718142107bd7b24572074be60bdb7611f1c916061a5ab3dc75a62b953a19650d839027a885801252a1e1cd84f8ba570047c2f1d220f26f7b11e69b7519f092d31ff954e92fd012a931ea2b4d20942376502043ba98e69f351f60b12e5a7ff180e5a1a966697d80696066694fa833420f5db7e3ae1b91dbce06fe2ffa1ea0a503af6a93f61ad7aa4f4").into(),  // First 20-30 characters
        };

        let receipt = create_receipt(function_name!(), &input);

        let result: bool = receipt.journal.decode().unwrap();

        assert!(!result, "Proof should be invalid due to an invalid verifying key");
    }

    fn create_receipt(test: &str, input: &VerifyZkpRequest) -> Receipt {
        let start = Instant::now();

        let env = ExecutorEnv::builder()
            .write(&input)
            .unwrap()
            .build()
            .unwrap();

        let prover = default_prover();

        let prove_info = prover.prove(env, GUEST_CODE_FOR_ZK_PROOF_ELF).unwrap();

        let duration = start.elapsed();

        log_results(test, &prove_info, duration).unwrap();

        prove_info.receipt
    }

    fn log_results(test: &str, prove_info: &ProveInfo, duration: std::time::Duration) -> std::io::Result<()> {
        // Open the file in append mode, creating it if it doesn't exist
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("out.csv")?;

        // Lock the file for exclusive access
        file.lock_exclusive()?;

        let metadata = file.metadata()?;
        if metadata.len() == 0 {
            writeln!(file, "timestamp,test,duration_millis,segments,total_cycles,user_cycles")?;
        }

        let line = format!(
            "{},{},{},{},{},{}",
            Utc::now().to_rfc3339(),
            test,
            duration.as_millis(),
            prove_info.stats.segments,
            prove_info.stats.total_cycles,
            prove_info.stats.user_cycles
        );        
        
        println!("{line}");
        writeln!(file, "{}", line)?;

        // Unlock the file after writing
        file.unlock()?;

        Ok(())
    }
}
