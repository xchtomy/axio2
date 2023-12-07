package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jp.co.axio.masterMentsetSystem.model.MPositionEntity;
import jp.co.axio.masterMentsetSystem.model.MPositionEntityExample;
import jp.co.axio.masterMentsetSystem.model.MPositionEntityKey;

@Mapper
public interface MPositionEntityMapper {
    long countByExample(MPositionEntityExample example);

    int deleteByExample(MPositionEntityExample example);

    int deleteByPrimaryKey(MPositionEntityKey key);

    int insert(MPositionEntity record);

    int insertSelective(MPositionEntity record);

    List<MPositionEntity> selectByExample(MPositionEntityExample example);

    MPositionEntity selectByPrimaryKey(MPositionEntityKey key);

    int updateByExampleSelective(@Param("record") MPositionEntity record, @Param("example") MPositionEntityExample example);

    int updateByExample(@Param("record") MPositionEntity record, @Param("example") MPositionEntityExample example);

    int updateByPrimaryKeySelective(MPositionEntity record);

    int updateByPrimaryKey(MPositionEntity record);

	List<MPositionEntity> selectMPositionByAuthPosCodeList(
															 @Param("codeMapList") List<Map<String, String>> codeMapList
															,@Param("searchFlag") boolean searchFlag
															,@Param("searchCompanyCode") String searchCompanyCode
															,@Param("searchPositionCode") String searchPositionCode
															,@Param("searchPositionName") String searchPositionName
															,@Param("searchStartDateYmd") String searchStartDateYmd
															,@Param("searchEndDateYmd") String searchEndDateYmd
															);
}