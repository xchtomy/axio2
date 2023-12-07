package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;

import lombok.Data;

/**
 * 組織セキュリティグループ設定画面
 * 詳細条件
 */
@Data
public class SecurityGroupOptionParam implements Serializable {

    /**
     * ID
     */
    private Long id;


     /**
      * 値
      */
    private String value;
    
}
