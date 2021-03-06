resource "hydra_jwks" "generated" {
  name = "generated"

  generator {
    alg = "RS256"
    kid = "generated"
    use = "sig"

    keepers = {
      version = 1
    }
  }
}

resource "hydra_jwks" "inlined" {
  name = "inlined"

  key {
    alg = "RS256"
    e   = "AQAB"
    kid = "public:inlined"
    kty = "RSA"
    n   = "2yyIpDSNMmWEy22TXVSH1p938ZxWgrfxoQl-Egbc3Gk2nA8MpK_YZCg5oLfyW0kv0mpjq6SsvK0qDKJwjdkeOzLp3qy8Vd-tkP2EF7intFXnkSm_LVPL88d81ysgPXopNL9pgJWTAzTwUZEZtAl5lzG6CLFxThho6XyZOxU-zP-sUK84E8qNfttQ4sdVT0bnl2_j7QOwnid1-c40ZViIb-y_8KHBDpW0RCtDCeaHv-vtgmaFdif-VkliLR8TJfJoWUpxGtmHQVrFXdzyYBCV_zbOxPi4xl-3IGOFZaE4RpvzD_uXI7z2VK2xTldHhcpIeREECAILK9uXo0y-rPbXNRNEQqTcV5WpD9j97n0Sk8NH-itk1no_xy85ubCe_VooOtWMQA7oT1bjco8gBJ7Ww1oNOh9oxtoOpYS9wiShBFTKtFBwhYNlMgERkpTVfR-HWuBSmOXxygfmPsskPUw4xZncmFkFpJi0F4rMtiGO3INWaPEEHZ-bcAqjCNJ4zgl_kECEr7cXAeGHlj69y_n4nRzyVO_l5TJcVCdRiCVxVzbTmX8Cu-MBlX8spTmkHeBdYKHdSNpFfvrwrS_XPjMsldQnnb8ZNmNRP1hZ5EawT3hK6e1hW90DPjGbl07jWrDpozyIFOj-ZKRmqt38CEdyhz3nRg2IJYxuNW6Ljma_wA8"
    use = "sig"
  }

  key {
    alg = "RS256"
    d   = "FMty43GA_AkZwltRIgfFI53ZuXjF1H0zVb4a0gcIqXjqD4B2CKIOe-I9JXyOaA7XlLU3Y6-qG_SqCqzW1P6GmcNI4TGuZM9mHl2PTNjeQIPuBp3ZX6mVrjl9JMUYt_yBMFoA3oxSeHlrW7HSqHxFpwy2w-BiCbDTM2P4_dwUK0sOxFD7lxUeu6x_TiTveSgXDQ02qOQyu66uyNbBrePqfgQOafxO3t1hTx5zq9rNgm4WCMtFWmKNBQ7NW86Y-H65W89uT8fXx2GfXDp8XJT2RlKi55lZnqiyLUaD_5J-TmS5eQi73E4vaPVZ3z70sELzAVmV8lSPTsf06S9839hDrr512IkoybqRn8LDtlTey9piX_FpsuDWMifhwlTZhNyB7qhfwo-qLOLR9sWJ4ayYVeR54Le8GxskEErx7vXHaeiFLEKL3n4DbapvT9KfrxeaKBiX-81XaHWbSfjWxVu2AsixeZq_3Hv-NECLkik5BYAxIK3RGWG7R4Olv9s8SWvoF3gbQXPFFTJLa3fQfPY9O6AAXESCl7I44bU9pjR-CdW7TkRnGCZziZot_ElvGPhUV_6USPHgqvDvqtP6532Ok7jDkSCkuo-_PK05Nsfh_68naiHHi4vL5deZbRZkmTGbna5MlY4SpPNPLBhqoAfPeUQFtZibZ93hbVMaBZuIKwE"
    e   = "AQAB"
    kid = "private:inlined"
    kty = "RSA"
    n   = "2yyIpDSNMmWEy22TXVSH1p938ZxWgrfxoQl-Egbc3Gk2nA8MpK_YZCg5oLfyW0kv0mpjq6SsvK0qDKJwjdkeOzLp3qy8Vd-tkP2EF7intFXnkSm_LVPL88d81ysgPXopNL9pgJWTAzTwUZEZtAl5lzG6CLFxThho6XyZOxU-zP-sUK84E8qNfttQ4sdVT0bnl2_j7QOwnid1-c40ZViIb-y_8KHBDpW0RCtDCeaHv-vtgmaFdif-VkliLR8TJfJoWUpxGtmHQVrFXdzyYBCV_zbOxPi4xl-3IGOFZaE4RpvzD_uXI7z2VK2xTldHhcpIeREECAILK9uXo0y-rPbXNRNEQqTcV5WpD9j97n0Sk8NH-itk1no_xy85ubCe_VooOtWMQA7oT1bjco8gBJ7Ww1oNOh9oxtoOpYS9wiShBFTKtFBwhYNlMgERkpTVfR-HWuBSmOXxygfmPsskPUw4xZncmFkFpJi0F4rMtiGO3INWaPEEHZ-bcAqjCNJ4zgl_kECEr7cXAeGHlj69y_n4nRzyVO_l5TJcVCdRiCVxVzbTmX8Cu-MBlX8spTmkHeBdYKHdSNpFfvrwrS_XPjMsldQnnb8ZNmNRP1hZ5EawT3hK6e1hW90DPjGbl07jWrDpozyIFOj-ZKRmqt38CEdyhz3nRg2IJYxuNW6Ljma_wA8"
    p   = "-Re8lp-XGIvSFH5xQEUqP9kBo7HeNbuih2YAgLRzRPrruJvUP-7tWMrbEb8jMYU7NCJ15l6Pl5T4dfBaaDoymkMi608uKESCTamMY7Y8iCKMke0j-3masjrIPaIlqjxTcIqJG7sqv7yq6rjRQFTsHLK-Opgux58_yg9UEd7oTgYPdiwwhLKmhrRelJbzKRHClj_btRUr-INU_Xlolmy9wLLxFc-a26RsuE3Y0Stjrg7PWij9082D2agUR5aOSnlRL5hHZv-KL9GIU3pv5Xh7LsCHarYPp_4kCeExxLAHlzPsjw3T2Ex8-AjwenQtL-VU9DE3VxWwkScSoJHQDI72QQ"
    q   = "4UBoyHCCGawXIiRf0UzY33tkE7HOFjIsJTyeJ3DuyQ-JJrh5Ab-jftfjWMq40CDD-h7sAn7xDaVsNqV5NEaN4cMRnMmv4MV3DjBZxXCI_8Bh1NtagxS5dkmTiCAZA0Hr_3r4lhPAF0VPMtFVPk5UenUwuc6HY3HNprX7CBFZFb21JskTc6q4GNgV2pIGEu6EWJYjEInmujHDiwilMXfIKJjgakvkHVypvEPlDVhEouVnaZ4Ulz27VOL_Ws0E3dQR3Xy7iIXm-TWXDTGhn1qYYKIg6tgznTR2pT8vcukm399oX9GK0PRQAIOhNY3uQnjQUntIAmg6Iv7fbWpwo-VCTw"
    use = "sig"
  }
}
