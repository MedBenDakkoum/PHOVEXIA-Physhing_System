"""Model architectures — exact copies of the Kaggle notebook definitions.

Source cells of docs/phish360-deeplearning-training.ipynb:
  - URLCharCNN / MetadataMLP: section 50 (aligned test predictions)
  - FusionMLP: section 54 (multimodal fusion)
Do not modify dimensions without re-exporting the whole bundle.
"""

from __future__ import annotations

import torch
import torch.nn.functional as F
from torch import nn


class URLCharCNN(nn.Module):
    def __init__(self, vocab_size: int) -> None:
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, 48, padding_idx=0)
        self.convs = nn.ModuleList(
            [nn.Conv1d(48, 64, kernel_size=k, padding=k // 2) for k in (3, 5, 7)]
        )
        self.dropout = nn.Dropout(0.35)
        self.fc1 = nn.Linear(192, 64)
        self.fc2 = nn.Linear(64, 2)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.embedding(x).transpose(1, 2)
        features = [F.relu(conv(x)).amax(dim=2) for conv in self.convs]
        x = torch.cat(features, dim=1)
        x = self.dropout(F.relu(self.fc1(self.dropout(x))))
        return self.fc2(x)


class MetadataMLP(nn.Module):
    def __init__(self, input_dim: int) -> None:
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 2),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


class FusionMLP(nn.Module):
    def __init__(self, input_dim: int = 4) -> None:
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 2),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)
