package com.tlovo.analyze.proto;

import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet.Field;

import java.util.Arrays;
import java.util.List;

/**
 * Protobuf的属性数据类
 * <br/>
 * 相当于消息类中的成员变量
 */
public class ProtoField {
    private final int tag;
    private String fieldName = "Unknown";

    // ===== 属性 =====
    // List里的多个值就是proto3里的repeated关键字

    /**
     * 变长整数
     * <br/>
     * int32、int64、uint32、uint64、bool、enum、sint32、sint64
     */
    private List<Long> varInt;

    /**
     * float
     * <br/>
     * fixed32
     */
    private List<Integer> fixed32;

    /**
     * double
     * <br/>
     * fixed64
     */
    private List<Long> fixed64;

    /**
     * 字节数组
     * <br/>
     * bytes、string
     */
    private List<ByteString> lengthDelimited;

    /**
     * 嵌套/子消息属性
     */
    private List<ProtoField> group;

    public ProtoField(int tag) {
        this.tag = tag;
    }

    public ProtoField(int tag, Field field) {
        this.tag = tag;
        this.varInt = field.getVarintList();
        this.fixed32 = field.getFixed32List();
        this.fixed64 = field.getFixed64List();
        this.lengthDelimited = field.getLengthDelimitedList();
    }

    public ProtoField(int tag,
                      List<Long> varInt, List<Integer> fixed32,
                      List<Long> fixed64, List<ByteString> lengthDelimited,
                      List<ProtoField> group) {
        this.tag = tag;
        this.varInt = varInt;
        this.fixed32 = fixed32;
        this.fixed64 = fixed64;
        this.lengthDelimited = lengthDelimited;
        this.group = group;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(fieldName).append(":").append(tag).append("]\n");

        if (!varInt.isEmpty()) {
            if (varInt.size() > 1) {
                sb.append("type = Repeated varInt, value = ");
                sb.append(Arrays.toString(varInt.toArray()));
            } else {
                sb.append("type = varInt, value = ");
                sb.append(varInt.get(0));
            }
        } else if (!fixed32.isEmpty()) {
            if (fixed32.size() > 1) {
                sb.append("type = Repeated fixed32, value = [");
                fixed32.forEach(f32 -> sb.append(Float.intBitsToFloat(f32)).append(", "));
                sb.delete(sb.length() - 2, sb.length()); // 去除多余的", "
                sb.append("]");
            } else {
                sb.append("type = fixed32, value = ");
                sb.append(Float.intBitsToFloat(fixed32.get(0)));
            }
        } else if (!fixed64.isEmpty()) {
            if (fixed64.size() > 1) {
                sb.append("type = Repeated fixed64, value = [");
                fixed64.forEach(f64 -> sb.append(Double.longBitsToDouble(f64)).append(", "));
                sb.delete(sb.length() - 2, sb.length()); // 去除多余的", "
                sb.append("]");
            } else {
                sb.append("type = fixed64, value = ");
                sb.append(Double.longBitsToDouble(fixed64.get(0)));
            }
        } else if (!lengthDelimited.isEmpty()) {
            if (lengthDelimited.size() > 1) {
                sb.append("type = Repeated bytes, value = [");
                lengthDelimited.forEach(ld -> sb.append(ld.toStringUtf8()).append(", "));
                sb.delete(sb.length() - 2, sb.length()); // 去除多余的", "
                sb.append("]");
            } else {
                sb.append("type = bytes, value = ");
                sb.append(lengthDelimited.get(0).toStringUtf8());
            }
        } else if (!group.isEmpty()) {
            if (group.size() > 1) {
                sb.append("type = Repeated Field, value = [\n");
                group.forEach(field -> sb.append("{\n").append(field.toString()).append("\n},\n"));
                sb.delete(sb.length() - 2, sb.length()); // 去除多余的",\n"
                sb.append("\n]");
            } else {
                sb.append("type = Field, value = ");
                sb.append(group.get(0).toString());
            }
        } else {
            sb.append("No value.");
        }

        return sb.toString();
    }
}
