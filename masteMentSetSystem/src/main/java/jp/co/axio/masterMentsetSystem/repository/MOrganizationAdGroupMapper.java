package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jp.co.axio.masterMentsetSystem.controller.AuthSecurityGrpListForm;
import jp.co.axio.masterMentsetSystem.controller.SecurityGrpBaseParam;
import jp.co.axio.masterMentsetSystem.dto.AuthSecurityGrpListDto;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MOrganizationAdGroupEntity;
import jp.co.axio.masterMentsetSystem.model.VOrganizationADGroupEntity;

@Mapper
public interface MOrganizationAdGroupMapper {
    
     /**
     * SGID指定検索
     * 表部分
     */
    List<MOrganizationAdGroupEntity> selectBaseParam(String sgid);


    /**
     * SGID指定検索
     * 表部分以外
     */
    MOrganizationAdGroupEntity selectBase(@Param("companyCode")String companyCode, @Param("organizationCode")String organizationCode);

    /**
     * 組織SGマスタ取得
     * @return
     */
    MOrganizationAdGroupEntity selectOrganizationAdGroup(@Param("companyCode") String companyCode, @Param("organizationCode") String organizationCode);


    /**
     * 組織SGマスタ取得
     * @return
     */
    Integer insertOrganizationAdGroup(MOrganizationAdGroupEntity entity);

    /**
     * 組織SGマスタ取得
     * @return
     */
    Integer updateOrganizationAdGroup(MOrganizationAdGroupEntity entity);


    /**
     * 重複したグループ名の名前を更新
     * @param entity
     * @return
     */
    Integer updateNameAdGroup(MOrganizationAdGroupEntity entity);

    /**
     * 重複しているグループを上書き
     * @param oldGroupId
     * @param newGroupId
     * @param newGroupName
     * @param newGroupNote
     * @return
     */
    Integer updateDuplicatedAdGroup(
        @Param("oldGroupId") String oldGroupId, @Param("newGroupId") String newGroupId,
        @Param("newGroupName") String newGroupName, @Param("newGroupNote") String newGroupNote);

    /**
     * 重複したグループIDの備考を更新
     * @param entity
     * @return
     */
    Integer updateNoteAdGroup(MOrganizationAdGroupEntity entity);

    /**
     * 重複したグループ名を持つ組織セキュリティグループの開始日、終了日を上書き
     * @return
     */
    Integer updateDateAdGroup(MOrganizationAdGroupEntity entity);


    /**
     * 未設定セキュリティグループ取得
     */
    List<MOrganizationAdGroupEntity> selectNotSetting();

    /**
     * 設定済みセキュリティグループ取得
     */
    List<MOrganizationAdGroupEntity> selectSetting();

    /**
     * SGコード発行
     */
    String selectNewSecurityGroupCode();


    /**
     * 基本設定表
     * @return
     */
    List<MOrganizationAdGroupEntity> selectBaseParamInit();

    /**
     * SGマスタ取得
     * @param sgid
     * @return
     */
    List<MOrganizationAdGroupEntity> selectAdGroup(String sgid);


    /**
     * SGマスタ挿入
     */
    Integer insertAdGroup(MOrganizationAdGroupEntity entity);

    /**
     * SGマスタ更新
     * @param entity
     * @return
     */
    Integer updateAdGroup(MOrganizationAdGroupEntity entity);


    /**
     * グループマスタに同じグループ名があるか検索
     */
    MGroupEntity selectDuplicatedGroupName(String groupName);

    /**
     * グループマスタに同じグループ名があるか検索
     */
    List<MOrganizationAdGroupEntity> selectDuplicatedGroupId(String securityGrpCode, String groupId);

    /**
     * セキュリティグループ検索
     * @param form
     * @return
     */
    List<AuthSecurityGrpListDto> selectGroupList(MOrganizationAdGroupEntity entity);


    /**
     * セキュリティグループ検索
     * セキュリティグループコード
     * @param sgid
     * @return
     */
    List<MOrganizationAdGroupEntity> selectBySecurityGroupCode(String sgid);


    /**
     * セキュリティグループ無効化
     * @param sgid
     * @return
     */
    Integer updateAdGroupInvalid(MOrganizationAdGroupEntity entity);

    /**
     * セキュリティグループ無効化単体
     * @param entity
     * @return
     */
    Integer updateOneAdGroupInvalid(MOrganizationAdGroupEntity entity);

    /**
     * セキュリティグループカウント
     * @return
     */
    Integer countAdGroupRecord(@Param("sgid") String sgid, @Param("groupType") String groupType);


    /**
     * 同じ組織を選択している設定をカウント
     * @param companyCode
     * @param organizationCode
     * @return
     */
    Integer countAdGroupOrg(@Param("companyCode") String companyCode, @Param("organizationCode") String organizationCode);


    /**
     * 同名のグループをカウント
     * @param companyCode
     * @param organizationCode
     * @return
     */
    Integer countAdGroupName(@Param("groupName") String groupName);

    /**
     * 組織紐づき解除
     * @param companyCode
     * @param organizationCode
     * @return
     */
    Integer updateAdGroupSetInvalid(@Param("companyCode") String companyCode, @Param("organizationCode") String organizationCode);

}
