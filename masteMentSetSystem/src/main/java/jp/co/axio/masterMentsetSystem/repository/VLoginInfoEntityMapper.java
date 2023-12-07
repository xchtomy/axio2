package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import jp.co.axio.masterMentsetSystem.model.VLoginInfoEntity;

@Mapper
public interface VLoginInfoEntityMapper {
	/* 自動生成
    long countByExample(VLoginInfoEntityExample example);

    int deleteByExample(VLoginInfoEntityExample example);

    int insert(VLoginInfoEntity record);

    int insertSelective(VLoginInfoEntity record);

    List<VLoginInfoEntity> selectByExample(VLoginInfoEntityExample example);

    int updateByExampleSelective(@Param("record") VLoginInfoEntity record, @Param("example") VLoginInfoEntityExample example);

    int updateByExample(@Param("record") VLoginInfoEntity record, @Param("example") VLoginInfoEntityExample example);
    */
	/**
	 * ユーザーIDを元にログイン情報を取得
	 * @param userId
	 * @return List<VLoginInfoEntity>
	 */
	List<VLoginInfoEntity> selectLoginInfoByUserId(String userId);
}