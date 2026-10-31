; ModuleID = 'hyperliquid_node94_u128_division.7ea5719ced459664-cgu.0'
source_filename = "hyperliquid_node94_u128_division.7ea5719ced459664-cgu.0"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "arm64-apple-macosx11.0.0"

; hyperliquid_node94_u128_division::quotient
; Function Attrs: nofree norecurse nosync nounwind memory(none) uwtable
define { i64, i64 } @_ZN32hyperliquid_node94_u128_division8quotient17hc60ce6367c5a86f5E(i64 noundef %numerator.0, i64 noundef %numerator.1, i64 noundef %denominator.0, i64 noundef %denominator.1) unnamed_addr #0 {
start:
  br label %bb16

bb17:                                             ; preds = %bb15
  %0 = insertvalue { i64, i64 } poison, i64 %result.sroa.0.1, 0
  %1 = insertvalue { i64, i64 } %0, i64 %result.sroa.6.1, 1
  ret { i64, i64 } %1

bb16:                                             ; preds = %start, %bb15
  %indvars.iv = phi i64 [ 128, %start ], [ %indvars.iv.next, %bb15 ]
  %result.sroa.0.016 = phi i64 [ 0, %start ], [ %result.sroa.0.1, %bb15 ]
  %result.sroa.6.015 = phi i64 [ 0, %start ], [ %result.sroa.6.1, %bb15 ]
  %remainder1.sroa.0.013 = phi i64 [ 0, %start ], [ %remainder1.sroa.0.1, %bb15 ]
  %remainder.sroa.0.012 = phi i64 [ 0, %start ], [ %remainder.sroa.0.1, %bb15 ]
  %indvars.iv.next = add nsw i64 %indvars.iv, -1
  %_7 = icmp samesign ugt i64 %indvars.iv, 64
  %2 = add i64 %indvars.iv, 63
  %3 = and i64 %2, 63
  %_8 = lshr i64 %numerator.1, %3
  %_11 = lshr i64 %numerator.0, %indvars.iv.next
  %incoming.sroa.0.0.in = select i1 %_7, i64 %_8, i64 %_11
  %incoming.sroa.0.0 = and i64 %incoming.sroa.0.0.in, 1
  %4 = tail call i64 @llvm.fshl.i64(i64 %remainder1.sroa.0.013, i64 %remainder.sroa.0.012, i64 1)
  %_17 = shl i64 %remainder.sroa.0.012, 1
  %5 = or disjoint i64 %incoming.sroa.0.0, %_17
  %_20 = icmp ugt i64 %4, %denominator.1
  br i1 %_20, label %bb9, label %bb6

bb6:                                              ; preds = %bb16
  %_22 = icmp eq i64 %4, %denominator.1
  %_24 = icmp uge i64 %5, %denominator.0
  %or.cond = select i1 %_22, i1 %_24, i1 false
  br i1 %or.cond, label %bb9, label %bb15

bb15:                                             ; preds = %bb11, %bb10, %bb6
  %remainder.sroa.0.1 = phi i64 [ %_44.0, %bb10 ], [ %_44.0, %bb11 ], [ %5, %bb6 ]
  %remainder1.sroa.0.1 = phi i64 [ %_27, %bb10 ], [ %_27, %bb11 ], [ %4, %bb6 ]
  %result.sroa.6.1 = phi i64 [ %7, %bb10 ], [ %result.sroa.6.015, %bb11 ], [ %result.sroa.6.015, %bb6 ]
  %result.sroa.0.1 = phi i64 [ %result.sroa.0.016, %bb10 ], [ %6, %bb11 ], [ %result.sroa.0.016, %bb6 ]
  %_34 = icmp ugt i64 %indvars.iv, 1
  br i1 %_34, label %bb16, label %bb17

bb9:                                              ; preds = %bb6, %bb16
  %_44.0 = sub i64 %5, %denominator.0
  %_44.1 = icmp ult i64 %5, %denominator.0
  %_28 = sub i64 %4, %denominator.1
  %_30.neg = sext i1 %_44.1 to i64
  %_27 = add i64 %_28, %_30.neg
  br i1 %_7, label %bb10, label %bb11

bb11:                                             ; preds = %bb9
  %_33 = shl nuw i64 1, %indvars.iv.next
  %6 = or i64 %_33, %result.sroa.0.016
  br label %bb15

bb10:                                             ; preds = %bb9
  %_31 = shl nuw i64 1, %3
  %7 = or i64 %_31, %result.sroa.6.015
  br label %bb15
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i64 @llvm.fshl.i64(i64, i64, i64) #1

attributes #0 = { nofree norecurse nosync nounwind memory(none) uwtable "frame-pointer"="non-leaf" "probe-stack"="inline-asm" "target-cpu"="apple-m1" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{!"rustc version 1.88.0 (6b00bc388 2025-06-23) (Homebrew)"}
